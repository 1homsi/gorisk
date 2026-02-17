package graph

import "github.com/1homsi/gorisk/internal/capability"

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
