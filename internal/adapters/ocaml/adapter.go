// Package ocaml implements a gorisk analyzer for OCaml/opam projects.
// It supports *.opam.locked, opam.locked, and *.opam files.
package ocaml

import (
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the analyzer.Analyzer interface for OCaml projects.
type Adapter struct{}

// Name returns the language identifier.
func (a Adapter) Name() string { return "ocaml" }

// Load parses the OCaml dependency lockfile in dir, detects capabilities from
// .ml/.mli source files, and returns a *graph.DependencyGraph.
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

	for _, ocamlPkg := range pkgs {
		key := ocamlPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    ocamlPkg.Name,
			Version: ocamlPkg.Version,
		}
		g.Modules[ocamlPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: ocamlPkg.Name,
			Name:       ocamlPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known OCaml packages.
		applyOCamlImportCaps(ocamlPkg, pkg)

		g.Packages[ocamlPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[ocamlPkg.Name] = ocamlPkg.Dependencies

		if ocamlPkg.Direct {
			rootEdges = append(rootEdges, ocamlPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyOCamlImportCaps applies import-level capabilities by matching the opam
// package name against known OCaml patterns.
func applyOCamlImportCaps(ocamlPkg OCamlPackage, pkg *graph.Package) {
	candidates := []string{
		ocamlPkg.Name,
		strings.ToLower(ocamlPkg.Name),
	}
	for _, candidate := range candidates {
		if importCaps, ok := ocamlPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    ocamlPkg.Name + "@" + ocamlPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}
