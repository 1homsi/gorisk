package erlang

import (
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Adapter interface for Erlang projects.
type Adapter struct{}

// Name returns the language identifier.
func (Adapter) Name() string { return "erlang" }

// Load parses the Erlang dependency file in dir, detects capabilities from
// Erlang source files, and returns a *graph.DependencyGraph.
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

	for _, erlangPkg := range pkgs {
		key := erlangPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    erlangPkg.Name,
			Version: erlangPkg.Version,
		}
		g.Modules[erlangPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: erlangPkg.Name,
			Name:       erlangPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Erlang packages.
		applyErlangImportCaps(erlangPkg, pkg)

		g.Packages[erlangPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[erlangPkg.Name] = erlangPkg.Dependencies

		if erlangPkg.Direct {
			rootEdges = append(rootEdges, erlangPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyErlangImportCaps applies import-level capabilities by matching the
// package name against known Erlang patterns.
func applyErlangImportCaps(erlangPkg ErlangPackage, pkg *graph.Package) {
	if importCaps, ok := erlangPatterns.Imports[erlangPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    erlangPkg.Name + "@" + erlangPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}

// BuildIRGraph builds a function-level IR graph for an Erlang dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildErlangFunctionIRGraph(g)
}

// buildErlangFunctionIRGraph converts packages into a function-level IRGraph.
func buildErlangFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		var files []string
		for _, pat := range []string{"*.erl", "*.hrl"} {
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
