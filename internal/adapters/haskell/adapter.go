// Package haskell implements a gorisk analyzer for Haskell projects.
// It supports cabal.project.freeze, stack.yaml.lock, and *.cabal files.
package haskell

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Adapter interface for Haskell projects.
type Adapter struct{}

// Name returns the language identifier for this adapter.
func (Adapter) Name() string { return "haskell" }

// Load parses the Haskell dependency lockfile in dir, detects capabilities from
// .hs and .lhs source files, and returns a *graph.DependencyGraph.
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

	for _, hsPkg := range pkgs {
		key := hsPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    hsPkg.Name,
			Version: hsPkg.Version,
		}
		g.Modules[hsPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: hsPkg.Name,
			Name:       hsPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities from known patterns.
		applyHaskellImportCaps(hsPkg, pkg)

		g.Packages[hsPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[hsPkg.Name] = hsPkg.Dependencies

		if hsPkg.Direct {
			rootEdges = append(rootEdges, hsPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyHaskellImportCaps applies import-level capabilities by matching the
// package name against known Haskell patterns (with normalisation variants).
func applyHaskellImportCaps(hsPkg HaskellPackage, pkg *graph.Package) {
	candidates := []string{
		hsPkg.Name,
		strings.ReplaceAll(hsPkg.Name, "_", "-"),
		strings.ReplaceAll(hsPkg.Name, "-", "_"),
		strings.ToLower(hsPkg.Name),
	}
	for _, candidate := range candidates {
		if importCaps, ok := haskellPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    hsPkg.Name + "@" + hsPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Haskell dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildHaskellFunctionIRGraph(g)
}

// buildHaskellFunctionIRGraph converts packages into a function-level IRGraph by
// running DetectFunctions on each package's .hs/.lhs source files.
func buildHaskellFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
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
				if name == "vendor" || name == "target" || name == "build" || name == ".stack-work" || (len(name) > 0 && name[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".hs" || ext == ".lhs" {
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
