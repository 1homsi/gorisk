package r

import (
	"os"
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the analyzer.Analyzer interface for R projects.
type Adapter struct{}

// Name returns the language identifier.
func (Adapter) Name() string { return "r" }

// Load parses the R dependency manifest in dir, detects capabilities from
// .R source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the R project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .R files.
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

	for _, rPkg := range pkgs {
		key := rPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    rPkg.Name,
			Version: rPkg.Version,
		}
		g.Modules[rPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: rPkg.Name,
			Name:       rPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known R packages.
		applyRImportCaps(rPkg, pkg)

		g.Packages[rPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[rPkg.Name] = rPkg.Dependencies

		if rPkg.Direct {
			rootEdges = append(rootEdges, rPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyRImportCaps applies import-level capabilities by matching the package
// name against known R patterns.
func applyRImportCaps(rPkg RPackage, pkg *graph.Package) {
	if importCaps, ok := rPatterns.Imports[rPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    rPkg.Name + "@" + rPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
		return
	}

	// Check installed package source directory if available.
	if _, statErr := os.Stat(pkg.Dir); pkg.Dir != "" && statErr == nil {
		pkg.Capabilities = Detect(pkg.Dir)
	}
}
