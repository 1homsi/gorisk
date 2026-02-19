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

	// Second pass: cross-package propagation for main module only
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
				propagated := PropagateAcrossPackages(pkgCaps, pkgEdges)
				// Merge propagated capabilities back into the graph
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
