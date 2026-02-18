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
	// Analyze runs reachability from all entrypoints (main packages / project source).
	Analyze(dir string) ([]ReachabilityReport, error)
	// AnalyzeFrom runs reachability starting from a specific entrypoint file.
	// If entryFile is empty it behaves identically to Analyze.
	AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error)
}

// GoAnalyzer implements Analyzer using Go SSA / callgraph analysis.
type GoAnalyzer struct{}

func (GoAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeGo(dir, "")
}

func (GoAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeGo(dir, entryFile)
}

// NodeAnalyzer implements Analyzer using JS/TS import-graph reachability.
type NodeAnalyzer struct{}

func (NodeAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeNode(dir, "")
}

func (NodeAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeNode(dir, entryFile)
}
