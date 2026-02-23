// Package cpp implements a gorisk analyzer for C/C++ projects.
// It supports vcpkg.json, conanfile.py, and conanfile.txt.
package cpp

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Adapter interface for C/C++ projects.
type Adapter struct{}

// Name returns the language identifier for this adapter.
func (Adapter) Name() string { return "cpp" }

// Load parses the C/C++ dependency manifest in dir, detects capabilities from
// source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

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

	for _, cppPkg := range pkgs {
		key := cppPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    cppPkg.Name,
			Version: cppPkg.Version,
		}
		g.Modules[cppPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: cppPkg.Name,
			Name:       cppPkg.Name,
			Module:     mod,
		}

		// Try to detect capabilities from installed package sources if available.
		if _, statErr := os.Stat(cppPkg.Name); statErr == nil {
			pkg.Capabilities = Detect(cppPkg.Name)
		}

		// Apply import-level capabilities from known patterns.
		applyCppImportCaps(cppPkg, pkg)

		g.Packages[cppPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[cppPkg.Name] = cppPkg.Dependencies

		if cppPkg.Direct {
			rootEdges = append(rootEdges, cppPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyCppImportCaps applies import-level capabilities by matching the package
// name against known C/C++ patterns (with normalisation variants).
func applyCppImportCaps(cppPkg CppPackage, pkg *graph.Package) {
	candidates := []string{
		cppPkg.Name,
		strings.ReplaceAll(cppPkg.Name, "_", "-"),
		strings.ReplaceAll(cppPkg.Name, "-", "_"),
		strings.ToLower(cppPkg.Name),
	}
	for _, candidate := range candidates {
		if importCaps, ok := cppPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    cppPkg.Name + "@" + cppPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// BuildIRGraph constructs a function-level IR graph from a DependencyGraph by
// parsing C/C++ source files in each package directory.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildCppFunctionIRGraph(g)
}

func buildCppFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{Functions: make(map[string]ir.FunctionCaps), Calls: []ir.CallEdge{}}
	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}
		var files []string
		for _, pat := range []string{"*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"} {
			fs, _ := filepath.Glob(filepath.Join(pkg.Dir, pat))
			files = append(files, fs...)
		}
		if len(files) == 0 {
			continue
		}
		var names []string
		for _, f := range files {
			names = append(names, filepath.Base(f))
		}
		funcs, edges, _ := DetectFunctions(pkg.Dir, names)
		for k, fc := range funcs {
			irGraph.Functions[k] = fc
		}
		irGraph.Calls = append(irGraph.Calls, edges...)
	}
	return irGraph
}
