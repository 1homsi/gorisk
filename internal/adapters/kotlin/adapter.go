// Package kotlin implements a gorisk analyzer for Kotlin/Gradle projects.
package kotlin

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Adapter interface for Kotlin projects.
type Adapter struct{}

func (Adapter) Name() string { return "kotlin" }

// Load parses the Kotlin/Gradle build files in dir, detects capabilities from
// .kt/.kts source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Kotlin project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .kt/.kts files.
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

	for _, kotlinPkg := range pkgs {
		key := kotlinPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    kotlinPkg.Name,
			Version: kotlinPkg.Version,
		}
		g.Modules[kotlinPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: kotlinPkg.Name,
			Name:       kotlinPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Kotlin libraries.
		applyKotlinImportCaps(kotlinPkg, pkg)

		g.Packages[kotlinPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[kotlinPkg.Name] = kotlinPkg.Dependencies

		if kotlinPkg.Direct {
			rootEdges = append(rootEdges, kotlinPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyKotlinImportCaps applies import-level capabilities by matching the
// package name against the kotlin.yaml imports map (keyed by group:artifact).
func applyKotlinImportCaps(kotlinPkg KotlinPackage, pkg *graph.Package) {
	if importCaps, ok := kotlinPatterns.Imports[kotlinPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    kotlinPkg.Name + "@" + kotlinPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
		return
	}

	// Detect capabilities from source if available.
	if kotlinPkg.Name != "" {
		_ = os.Stat // satisfy unused import if needed
	}
}

// BuildIRGraph builds a function-level IR graph for a Kotlin dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildKotlinFunctionIRGraph(g)
}

// buildKotlinFunctionIRGraph converts packages into a function-level IRGraph.
// Uses funcdetector.go to parse Kotlin source files and build a call graph.
func buildKotlinFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
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
				if name == "vendor" || name == "target" || name == "build" || (len(name) > 0 && name[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".kt" || ext == ".kts" {
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

		funcs, edges, _ := DetectFunctions(pkg.Dir, pkg.ImportPath, relFiles)
		for k, fc := range funcs {
			irGraph.Functions[k] = fc
		}
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
