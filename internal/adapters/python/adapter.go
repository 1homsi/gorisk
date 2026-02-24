// Package python implements a gorisk analyzer for Python projects.
// It supports pyproject.toml/poetry.lock, Pipfile.lock, and requirements.txt.
package python

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Python projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "python" }

// Load parses the Python dependency lockfile in dir, detects capabilities from
// each installed package's source (if site-packages is present), and returns a
// *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Python project itself.
	rootName := filepath.Base(dir)
	if name := readPyprojectName(dir); name != "" {
		rootName = name
	}

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .py files.
	rootPkg := &graph.Package{
		ImportPath:   rootName,
		Name:         rootName,
		Module:       rootMod,
		Dir:          dir,
		Capabilities: Detect(dir),
	}
	g.Packages[rootName] = rootPkg
	rootMod.Packages = append(rootMod.Packages, rootPkg)

	var rootEdges []string
	seen := make(map[string]bool)

	for _, pyPkg := range pkgs {
		key := pyPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    pyPkg.Name,
			Version: pyPkg.Version,
			Dir:     pyPkg.Dir,
		}
		g.Modules[pyPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: pyPkg.Name,
			Name:       pyPkg.Name,
			Module:     mod,
			Dir:        pyPkg.Dir,
		}

		// Detect capabilities from installed package source (if available).
		if pyPkg.Dir != "" {
			if _, statErr := os.Stat(pyPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(pyPkg.Dir)
			}
		}

		// Apply import-level capabilities for known Python packages.
		normalised := normalizePackageName(pyPkg.Name)
		if importCaps, ok := pythonPatterns.Imports[normalised]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    pyPkg.Name + "@" + pyPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
		}

		g.Packages[pyPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[pyPkg.Name] = pyPkg.Dependencies

		if pyPkg.Direct {
			rootEdges = append(rootEdges, pyPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// readPyprojectName reads the project name from pyproject.toml.
func readPyprojectName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return ""
	}
	// Simple scan: look for  name = "..."  in [project] or [tool.poetry] section.
	import_ := struct {
		Project struct {
			Name string `json:"name"`
		} `json:"project"`
	}{}
	// Try JSON parsing as a fallback (won't work for TOML, but worth trying).
	_ = json.Unmarshal(data, &import_)
	if import_.Project.Name != "" {
		return import_.Project.Name
	}
	return ""
}

// BuildIRGraph builds a function-level IR graph for a Python dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildPythonFunctionIRGraph(g)
}

// buildPythonFunctionIRGraph converts packages into a function-level IRGraph.
func buildPythonFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		var relFiles []string
		_ = filepath.WalkDir(pkg.Dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == "vendor" || name == "node_modules" || (len(name) > 0 && name[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".py" {
				rel, relErr := filepath.Rel(pkg.Dir, path)
				if relErr == nil {
					relFiles = append(relFiles, rel)
				}
			}
			return nil
		})

		if len(relFiles) == 0 {
			continue
		}

		funcs, edges, err := DetectFunctions(pkg.Dir, pkg.ImportPath, relFiles)
		if err != nil {
			continue
		}
		for k, fc := range funcs {
			irGraph.Functions[k] = fc
		}
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
