package goadapter

import "github.com/1homsi/gorisk/internal/graph"

// Adapter wraps graph.Load to implement the Analyzer interface for Go projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "go" }

func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	return graph.Load(dir)
}
