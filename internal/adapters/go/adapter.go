package goadapter

import (
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/interproc"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter wraps graph.Load to implement the Analyzer interface for Go projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "go" }

func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	g, err := graph.Load(dir)
	if err != nil {
		return nil, err
	}

	// First pass: detect per-package capabilities
	for _, pkg := range g.Packages {
		if pkg.Dir == "" || len(pkg.GoFiles) == 0 {
			continue
		}
		caps, err := DetectPackage(pkg.Dir, pkg.GoFiles)
		if err == nil {
			pkg.Capabilities = caps
		}
	}

	// Second pass: interprocedural analysis for main module
	if g.Main != nil {
		mainPkgs := make(map[string]*graphPackageAdapter)
		for _, pkg := range g.Packages {
			if pkg.Module != nil && pkg.Module.Main && pkg.Dir != "" && len(pkg.GoFiles) > 0 {
				mainPkgs[pkg.ImportPath] = &graphPackageAdapter{
					ImportPath: pkg.ImportPath,
					Dir:        pkg.Dir,
					GoFiles:    pkg.GoFiles,
					Module:     &graphModuleAdapter{Path: pkg.Module.Path, Main: pkg.Module.Main},
				}
			}
		}

		if len(mainPkgs) > 0 {
			pkgCaps, pkgEdges, err := BuildModuleGraph(dir, convertToPackageMap(mainPkgs))
			if err == nil {
				// Use interprocedural engine with context-sensitive analysis
				irGraph := interproc.ConsolidateIR(pkgCaps, pkgEdges)
				opts := interproc.DefaultOptions()
				csGraph, _, err := interproc.RunAnalysis(irGraph, opts)

				if err == nil {
					// Roll up context-sensitive summaries to package level
					propagated := rollupToPackages(csGraph)
					for pkgPath, funcs := range propagated {
						if pkg := g.Packages[pkgPath]; pkg != nil {
							for _, fc := range funcs {
								pkg.Capabilities.MergeWithEvidence(fc.TransitiveCaps)
							}
						}
					}
				}
			}
		}
	}

	return g, nil
}

// graphPackageAdapter adapts graph.Package to the minimal Package interface.
type graphPackageAdapter struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Module     *graphModuleAdapter
}

// graphModuleAdapter adapts graph.Module to the minimal Module interface.
type graphModuleAdapter struct {
	Path string
	Main bool
}

func convertToPackageMap(in map[string]*graphPackageAdapter) map[string]*Package {
	out := make(map[string]*Package)
	for k, v := range in {
		out[k] = &Package{
			ImportPath: v.ImportPath,
			Dir:        v.Dir,
			GoFiles:    v.GoFiles,
			Module:     &Module{Path: v.Module.Path, Main: v.Module.Main},
		}
	}
	return out
}

// rollupToPackages converts context-sensitive summaries back to package-level capabilities.
// This maintains backward compatibility with the existing package-based analysis.
func rollupToPackages(csGraph *ir.CSCallGraph) map[string]map[string]ir.FunctionCaps {
	result := make(map[string]map[string]ir.FunctionCaps)

	for nodeKey, node := range csGraph.Nodes {
		summary := csGraph.Summaries[nodeKey]
		pkg := node.Function.Package
		if pkg == "" {
			continue
		}

		if result[pkg] == nil {
			result[pkg] = make(map[string]ir.FunctionCaps)
		}

		// Convert FunctionSummary to FunctionCaps
		funcCaps := ir.FunctionCaps{
			Symbol:         node.Function,
			DirectCaps:     summary.Effects,
			TransitiveCaps: summary.Transitive,
			Depth:          summary.Depth,
		}

		result[pkg][node.Function.String()] = funcCaps
	}

	return result
}
