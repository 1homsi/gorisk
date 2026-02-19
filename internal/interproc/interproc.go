// Package interproc provides interprocedural analysis capabilities
// for context-sensitive call graph analysis and taint tracking.
package interproc

import (
	"github.com/1homsi/gorisk/internal/ir"
	"github.com/1homsi/gorisk/internal/taint"
)

// AnalysisOptions configures the interprocedural analysis.
type AnalysisOptions struct {
	ContextSensitivity int    // k for k-CFA (default: 1)
	MaxIterations      int    // Max fixpoint iterations (default: 1000)
	EnableCache        bool   // Enable persistent caching (default: true)
	CacheDir           string // Cache directory (default: $HOME/.cache/gorisk)
}

// DefaultOptions returns the default analysis configuration.
func DefaultOptions() AnalysisOptions {
	return AnalysisOptions{
		ContextSensitivity: 1,
		MaxIterations:      1000,
		EnableCache:        true,
		CacheDir:           "",
	}
}

// RunAnalysis performs interprocedural analysis on an IRGraph.
// It returns a context-sensitive call graph with computed summaries
// and interprocedural taint findings.
func RunAnalysis(irGraph ir.IRGraph, opts AnalysisOptions) (*ir.CSCallGraph, []taint.TaintFinding, error) {
	Infof("=== Starting Interprocedural Analysis ===")
	Debugf("[analysis] Options: k=%d, maxIter=%d, cache=%v", opts.ContextSensitivity, opts.MaxIterations, opts.EnableCache)

	// Step 1: Build context-sensitive call graph
	k := opts.ContextSensitivity
	if k < 0 {
		k = 0 // Context-insensitive
	} else if k > 2 {
		k = 1 // Limit to k=1 for now
	}

	Infof("[analysis] Step 1: Building k=%d call graph", k)
	csGraph := BuildCSCallGraph(irGraph, k)

	// Step 2: Detect strongly connected components
	Infof("[analysis] Step 2: Detecting SCCs")
	DetectSCCs(csGraph)

	// Step 3: Create cache manager
	Infof("[analysis] Step 3: Initializing cache (enabled=%v)", opts.EnableCache)
	var cache *Cache
	if opts.EnableCache {
		cache = NewCache(opts.CacheDir)
	} else {
		cache = NewCacheDisabled()
	}

	// Step 4: Compute fixpoint with caching
	maxIter := opts.MaxIterations
	if maxIter <= 0 {
		maxIter = 1000
	}

	Infof("[analysis] Step 4: Computing fixpoint")
	if err := ComputeFixpointCached(csGraph, cache, maxIter); err != nil {
		return nil, nil, err
	}

	// Log cache statistics
	cache.Stats()

	// Step 5: Run interprocedural taint analysis
	Infof("[analysis] Step 5: Running taint analysis")
	taintAnalysis := taint.NewInterprocedural(csGraph)
	findings := taintAnalysis.AnalyzeInterprocedural()

	Infof("[analysis] Found %d interprocedural taint flows", len(findings))
	Infof("=== Analysis Complete ===")

	return csGraph, findings, nil
}

// ComputeFixpointCached is a wrapper around ComputeFixpoint that uses caching.
// Currently, caching is implemented but the LoadOrCompute integration is deferred.
func ComputeFixpointCached(cg *ir.CSCallGraph, cache *Cache, maxIterations int) error {
	// For now, just run the regular fixpoint without per-node caching
	// Full caching integration requires more sophisticated invalidation
	return ComputeFixpoint(cg, maxIterations)
}
