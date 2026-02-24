// Package ruby implements a gorisk analyzer for Ruby projects.
// It supports Gemfile.lock and Gemfile.
package ruby

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Ruby projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "ruby" }

// Load parses the Ruby dependency lockfile in dir, detects capabilities from
// .rb source files, and returns a *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Ruby project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .rb files.
	rootPkg := &graph.Package{
		ImportPath:   rootName,
		Name:         rootName,
		Module:       rootMod,
		Dir:          dir,
		Capabilities: Detect(dir),
	}
	g.Packages[rootName] = rootPkg
	rootMod.Packages = append(rootMod.Packages, rootPkg)

	var rootEdges []string
	seen := make(map[string]bool)

	for _, rubyPkg := range pkgs {
		key := rubyPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    rubyPkg.Name,
			Version: rubyPkg.Version,
			Dir:     rubyPkg.Dir,
		}
		g.Modules[rubyPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: rubyPkg.Name,
			Name:       rubyPkg.Name,
			Module:     mod,
			Dir:        rubyPkg.Dir,
		}

		// Detect capabilities from installed package source (if available).
		if rubyPkg.Dir != "" {
			if _, statErr := os.Stat(rubyPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(rubyPkg.Dir)
			}
		}

		// Apply import-level capabilities for known Ruby gems.
		applyRubyImportCaps(rubyPkg, pkg)

		g.Packages[rubyPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[rubyPkg.Name] = rubyPkg.Dependencies

		if rubyPkg.Direct {
			rootEdges = append(rootEdges, rubyPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyRubyImportCaps applies import-level capabilities by matching the gem
// name against known Ruby patterns (with normalisation variants).
func applyRubyImportCaps(rubyPkg RubyPackage, pkg *graph.Package) {
	candidates := []string{
		rubyPkg.Name,
		strings.ReplaceAll(rubyPkg.Name, "_", "-"),
		strings.ReplaceAll(rubyPkg.Name, "-", "_"),
	}
	for _, candidate := range candidates {
		if importCaps, ok := rubyPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    rubyPkg.Name + "@" + rubyPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Ruby dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildRubyFunctionIRGraph(g)
}

// buildRubyFunctionIRGraph converts packages into a function-level IRGraph.
func buildRubyFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		var relFiles []string
		_ = filepath.WalkDir(pkg.Dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == "vendor" || name == "node_modules" || (len(name) > 0 && name[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".rb" {
				rel, relErr := filepath.Rel(pkg.Dir, path)
				if relErr == nil {
					relFiles = append(relFiles, rel)
				}
			}
			return nil
		})

		if len(relFiles) == 0 {
			continue
		}

		funcs, edges, err := DetectFunctions(pkg.Dir, pkg.ImportPath, relFiles)
		if err != nil {
			continue
		}
		for k, fc := range funcs {
			irGraph.Functions[k] = fc
		}
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
