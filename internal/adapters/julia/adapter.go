// Package julia implements a gorisk analyzer for Julia projects.
// It supports Manifest.toml and Project.toml.
package julia

import (
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Julia projects.
type Adapter struct{}

// Name returns the language identifier.
func (a Adapter) Name() string { return "julia" }

// Load parses the Julia dependency lockfile in dir, detects capabilities from
// .jl source files, and returns a *graph.DependencyGraph.
func (a Adapter) Load(dir string) (*graph.DependencyGraph, error) {
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

	for _, juliaPkg := range pkgs {
		key := juliaPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    juliaPkg.Name,
			Version: juliaPkg.Version,
		}
		g.Modules[juliaPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: juliaPkg.Name,
			Name:       juliaPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Julia packages.
		applyJuliaImportCaps(juliaPkg, pkg)

		g.Packages[juliaPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[juliaPkg.Name] = juliaPkg.Dependencies

		if juliaPkg.Direct {
			rootEdges = append(rootEdges, juliaPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyJuliaImportCaps applies import-level capabilities by matching the Julia
// package name against known Julia patterns.
func applyJuliaImportCaps(juliaPkg JuliaPackage, pkg *graph.Package) {
	if importCaps, ok := juliaPatterns.Imports[juliaPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    juliaPkg.Name + "@" + juliaPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}

// BuildIRGraph constructs a function-level IR graph from a DependencyGraph by
// parsing Julia source files in each package directory.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildJuliaFunctionIRGraph(g)
}

func buildJuliaFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{Functions: make(map[string]ir.FunctionCaps), Calls: []ir.CallEdge{}}
	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}
		fs, _ := filepath.Glob(filepath.Join(pkg.Dir, "*.jl"))
		if len(fs) == 0 {
			continue
		}
		var names []string
		for _, f := range fs {
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
