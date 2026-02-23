// Package rust implements a gorisk analyzer for Rust projects.
// It supports Cargo.lock and Cargo.toml.
package rust

import (
	"os"
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Rust projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "rust" }

// Load parses the Rust dependency lockfile in dir, detects capabilities from
// .rs source files, and returns a *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Rust crate itself.
	rootName := filepath.Base(dir)
	if name := readCargoTomlName(dir); name != "" {
		rootName = name
	}

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the crate's own .rs files.
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

	for _, rustPkg := range pkgs {
		key := rustPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    rustPkg.Name,
			Version: rustPkg.Version,
			Dir:     rustPkg.Dir,
		}
		g.Modules[rustPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: rustPkg.Name,
			Name:       rustPkg.Name,
			Module:     mod,
			Dir:        rustPkg.Dir,
		}

		// Detect capabilities from installed package source (if available).
		if rustPkg.Dir != "" {
			if _, statErr := os.Stat(rustPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(rustPkg.Dir)
			}
		}

		// Apply import-level capabilities for known Rust crates.
		if importCaps, ok := rustPatterns.Imports[rustPkg.Name]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    rustPkg.Name + "@" + rustPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
		}

		g.Packages[rustPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[rustPkg.Name] = rustPkg.Dependencies

		if rustPkg.Direct {
			rootEdges = append(rootEdges, rustPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// BuildIRGraph builds a function-level IR graph for a Rust dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildRustFunctionIRGraph(g)
}

// buildRustFunctionIRGraph converts packages into a function-level IRGraph by
// running DetectFunctions on each package's .rs source files.
func buildRustFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		files, _ := filepath.Glob(filepath.Join(pkg.Dir, "*.rs"))
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
