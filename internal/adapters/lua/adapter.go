package lua

import (
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Lua projects.
type Adapter struct{}

// Name returns the language identifier.
func (Adapter) Name() string { return "lua" }

// Load parses the Lua dependency manifest in dir, detects capabilities from
// .lua source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Lua project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .lua files.
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

	for _, lPkg := range pkgs {
		key := lPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    lPkg.Name,
			Version: lPkg.Version,
		}
		g.Modules[lPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: lPkg.Name,
			Name:       lPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Lua packages.
		applyLuaImportCaps(lPkg, pkg)

		g.Packages[lPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[lPkg.Name] = lPkg.Dependencies

		if lPkg.Direct {
			rootEdges = append(rootEdges, lPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyLuaImportCaps applies import-level capabilities by matching the package
// name against known Lua patterns.
func applyLuaImportCaps(lPkg LuaPackage, pkg *graph.Package) {
	if importCaps, ok := luaPatterns.Imports[lPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    lPkg.Name + "@" + lPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Lua dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildLuaFunctionIRGraph(g)
}

// buildLuaFunctionIRGraph converts packages into a function-level IRGraph.
func buildLuaFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(pkg.Dir, "*.lua")) //nolint:errcheck
		if len(files) == 0 {
			continue
		}
		var names []string
		for _, f := range files {
			names = append(names, filepath.Base(f))
		}
		funcs, edges, err := DetectFunctions(pkg.Dir, names)
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
