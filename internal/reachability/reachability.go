package reachability

import "github.com/1homsi/gorisk/internal/capability"

// ReachabilityReport describes how a dependency's capabilities are reachable
// from the project's source code.
type ReachabilityReport struct {
	Package       string
	ReachableCaps capability.CapabilitySet
	Reachable     bool
}

// Analyzer is the interface that language implementations satisfy.
type Analyzer interface {
	Analyze(dir string) ([]ReachabilityReport, error)
}

// GoAnalyzer implements Analyzer using Go SSA / callgraph analysis.
type GoAnalyzer struct{}

func (GoAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) { return analyzeGo(dir) }

// NodeAnalyzer implements Analyzer using JS/TS import-graph reachability.
type NodeAnalyzer struct{}

func (NodeAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) { return analyzeNode(dir) }
