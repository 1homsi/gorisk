package goadapter

import "github.com/1homsi/gorisk/internal/graph"

// Adapter wraps graph.Load to implement the Analyzer interface for Go projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "go" }

func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	g, err := graph.Load(dir)
	if err != nil {
		return nil, err
	}
	for _, pkg := range g.Packages {
		if pkg.Dir == "" || len(pkg.GoFiles) == 0 {
			continue
		}
		caps, err := DetectPackage(pkg.Dir, pkg.GoFiles)
		if err == nil {
			pkg.Capabilities = caps
		}
	}
	return g, nil
}
