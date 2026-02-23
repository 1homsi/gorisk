package perl

import (
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the analyzer.Analyzer interface for Perl projects.
type Adapter struct{}

// Name returns the language identifier.
func (Adapter) Name() string { return "perl" }

// Load parses the Perl dependency manifest in dir, detects capabilities from
// .pl/.pm/.t source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Perl project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own Perl files.
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

	for _, pPkg := range pkgs {
		key := pPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    pPkg.Name,
			Version: pPkg.Version,
		}
		g.Modules[pPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: pPkg.Name,
			Name:       pPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Perl modules.
		applyPerlImportCaps(pPkg, pkg)

		g.Packages[pPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[pPkg.Name] = pPkg.Dependencies

		if pPkg.Direct {
			rootEdges = append(rootEdges, pPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyPerlImportCaps applies import-level capabilities by matching the module
// name against known Perl patterns.
func applyPerlImportCaps(pPkg PerlPackage, pkg *graph.Package) {
	if importCaps, ok := perlPatterns.Imports[pPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    pPkg.Name + "@" + pPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}
