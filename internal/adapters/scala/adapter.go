// Package scala implements a gorisk analyzer for Scala/sbt projects.
package scala

import (
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the analyzer.Adapter interface for Scala projects.
type Adapter struct{}

func (Adapter) Name() string { return "scala" }

// Load parses the Scala/sbt build files in dir, detects capabilities from
// .scala source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Scala project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .scala files.
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

	for _, scalaPkg := range pkgs {
		key := scalaPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    scalaPkg.Name,
			Version: scalaPkg.Version,
		}
		g.Modules[scalaPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: scalaPkg.Name,
			Name:       scalaPkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Scala libraries.
		applyScalaImportCaps(scalaPkg, pkg)

		g.Packages[scalaPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[scalaPkg.Name] = scalaPkg.Dependencies

		if scalaPkg.Direct {
			rootEdges = append(rootEdges, scalaPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyScalaImportCaps applies import-level capabilities by matching the
// package name against the scala.yaml imports map (keyed by org:name).
func applyScalaImportCaps(scalaPkg ScalaPackage, pkg *graph.Package) {
	if importCaps, ok := scalaPatterns.Imports[scalaPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    scalaPkg.Name + "@" + scalaPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}
