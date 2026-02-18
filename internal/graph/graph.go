package graph

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/1homsi/gorisk/internal/capability"
)

type Module struct {
	Path     string
	Version  string
	Dir      string
	Main     bool
	Indirect bool
	Packages []*Package
}

type Package struct {
	ImportPath   string
	Name         string
	Module       *Module
	Dir          string
	GoFiles      []string
	Imports      []string
	Deps         []string
	Capabilities capability.CapabilitySet
}

type DependencyGraph struct {
	Main     *Module
	Modules  map[string]*Module
	Packages map[string]*Package
	Edges    map[string][]string
}

func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Modules:  make(map[string]*Module),
		Packages: make(map[string]*Package),
		Edges:    make(map[string][]string),
	}
}

func (g *DependencyGraph) ReverseEdges() map[string][]string {
	rev := make(map[string][]string)
	for pkg, imports := range g.Edges {
		for _, imp := range imports {
			rev[imp] = append(rev[imp], pkg)
		}
	}
	return rev
}

// Checksum returns a short deterministic SHA-256 digest of the dependency graph.
// The digest covers module paths, versions, package import paths, capability names,
// and edge targets — all sorted for stability across runs.
func (g *DependencyGraph) Checksum() string {
	type pkgEntry struct {
		ImportPath string   `json:"i"`
		Caps       []string `json:"c,omitempty"`
		Deps       []string `json:"d,omitempty"`
	}
	type modEntry struct {
		Path     string     `json:"p"`
		Version  string     `json:"v,omitempty"`
		Packages []pkgEntry `json:"pkgs,omitempty"`
	}

	// Collect non-main module paths sorted for determinism
	modPaths := make([]string, 0, len(g.Modules))
	for path, mod := range g.Modules {
		if !mod.Main {
			modPaths = append(modPaths, path)
		}
	}
	sort.Strings(modPaths)

	entries := make([]modEntry, 0, len(modPaths))
	for _, modPath := range modPaths {
		mod := g.Modules[modPath]
		me := modEntry{Path: modPath, Version: mod.Version}

		// Sort packages within the module
		pkgPaths := make([]string, 0, len(mod.Packages))
		pkgByPath := make(map[string]*Package, len(mod.Packages))
		for _, pkg := range mod.Packages {
			pkgPaths = append(pkgPaths, pkg.ImportPath)
			pkgByPath[pkg.ImportPath] = pkg
		}
		sort.Strings(pkgPaths)

		for _, pkgPath := range pkgPaths {
			pkg := pkgByPath[pkgPath]

			caps := pkg.Capabilities.List()
			if caps == nil {
				caps = []string{}
			}
			// Caps are already sorted by CapabilitySet but ensure it
			sort.Strings(caps)

			edgesCopy := make([]string, len(g.Edges[pkgPath]))
			copy(edgesCopy, g.Edges[pkgPath])
			sort.Strings(edgesCopy)

			me.Packages = append(me.Packages, pkgEntry{
				ImportPath: pkgPath,
				Caps:       caps,
				Deps:       edgesCopy,
			})
		}
		entries = append(entries, me)
	}

	data, _ := json.Marshal(entries)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:8]) // 16 hex chars
}
