package elixir

import (
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Elixir projects.
type Adapter struct{}

func (Adapter) Name() string { return "elixir" }

// Load parses the Elixir dependency lockfile in dir, detects capabilities from
// .ex/.exs source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Elixir project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .ex/.exs files.
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

	for _, elixirPkg := range pkgs {
		key := elixirPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    elixirPkg.Name,
			Version: elixirPkg.Version,
		}
		g.Modules[elixirPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: elixirPkg.Name,
			Name:       elixirPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Elixir packages.
		applyElixirImportCaps(elixirPkg, pkg)

		g.Packages[elixirPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[elixirPkg.Name] = elixirPkg.Dependencies

		if elixirPkg.Direct {
			rootEdges = append(rootEdges, elixirPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyElixirImportCaps applies import-level capabilities by matching the
// package name against known Elixir patterns (with normalisation variants).
func applyElixirImportCaps(elixirPkg ElixirPackage, pkg *graph.Package) {
	candidates := []string{
		elixirPkg.Name,
		strings.ReplaceAll(elixirPkg.Name, "_", "-"),
		strings.ReplaceAll(elixirPkg.Name, "-", "_"),
	}
	for _, candidate := range candidates {
		if importCaps, ok := elixirPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    elixirPkg.Name + "@" + elixirPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// BuildIRGraph builds a function-level IR graph for an Elixir dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildElixirFunctionIRGraph(g)
}

// buildElixirFunctionIRGraph converts packages into a function-level IRGraph.
func buildElixirFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		var files []string
		for _, pat := range []string{"*.ex", "*.exs"} {
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
