package php

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the Analyzer interface for PHP projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "php" }

// Load parses the project's composer.lock, detects capabilities for each
// Composer package found in vendor/, and returns a *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the project itself.
	rootName := filepath.Base(dir)
	if name := readComposerJSONName(dir); name != "" {
		rootName = name
	}

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — the project's own PHP source files.
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

	for _, composerPkg := range pkgs {
		if seen[composerPkg.Name] {
			continue
		}
		seen[composerPkg.Name] = true

		mod := &graph.Module{
			Path:    composerPkg.Name,
			Version: composerPkg.Version,
			Dir:     composerPkg.Dir,
		}
		g.Modules[composerPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: composerPkg.Name,
			Name:       composerPkg.Name,
			Module:     mod,
			Dir:        composerPkg.Dir,
		}

		// Detect capabilities from the package's source files (if vendor/ is present).
		if composerPkg.Dir != "" {
			if _, statErr := os.Stat(composerPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(composerPkg.Dir)
			}
		}

		// Also apply import-level capabilities for known Composer packages.
		if importCaps, ok := phpPatterns.Imports[composerPkg.Name]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "composer.lock",
					Context:    composerPkg.Name + "@" + composerPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
		}

		g.Packages[composerPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[composerPkg.Name] = composerPkg.Dependencies

		if composerPkg.Direct {
			rootEdges = append(rootEdges, composerPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

func readComposerJSONName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		return ""
	}
	var composerJSON struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &composerJSON) != nil {
		return ""
	}
	return composerJSON.Name
}
