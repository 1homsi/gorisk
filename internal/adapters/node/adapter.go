package node

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the Analyzer interface for Node.js projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "node" }

// Load parses the project's lockfile, detects capabilities for each npm
// package, and returns a *graph.DependencyGraph using the same structure as
// the Go loader.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Build root module from package.json name (or directory basename)
	rootName := filepath.Base(dir)
	if name := readPackageJSONName(dir); name != "" {
		rootName = name
	}

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — represents the project's own source files
	rootPkg := &graph.Package{
		ImportPath:   rootName,
		Name:         rootName,
		Module:       rootMod,
		Dir:          dir,
		Capabilities: Detect(dir),
	}
	g.Packages[rootName] = rootPkg
	rootMod.Packages = append(rootMod.Packages, rootPkg)

	// Track which packages are direct dependencies of root
	var rootEdges []string

	// Deduplicate packages by name (keep first seen)
	seen := make(map[string]bool)

	for _, npmPkg := range pkgs {
		if seen[npmPkg.Name] {
			continue
		}
		seen[npmPkg.Name] = true

		mod := &graph.Module{
			Path:    npmPkg.Name,
			Version: npmPkg.Version,
			Dir:     npmPkg.Dir,
		}
		g.Modules[npmPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: npmPkg.Name,
			Name:       npmPkg.Name,
			Module:     mod,
			Dir:        npmPkg.Dir,
		}

		// Detect capabilities from the package's source files (if present)
		if npmPkg.Dir != "" {
			if _, statErr := os.Stat(npmPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(npmPkg.Dir)
			}
		}

		g.Packages[npmPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[npmPkg.Name] = npmPkg.Dependencies

		if npmPkg.Direct {
			rootEdges = append(rootEdges, npmPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges
	return g, nil
}

func readPackageJSONName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ""
	}
	var pkgJSON struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &pkgJSON) != nil {
		return ""
	}
	return pkgJSON.Name
}
