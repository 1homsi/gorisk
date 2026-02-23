package clojure

import (
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Adapter interface for Clojure projects.
type Adapter struct{}

// Name returns the language identifier.
func (Adapter) Name() string { return "clojure" }

// Load parses the Clojure dependency file in dir, detects capabilities from
// Clojure source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	rootName := filepath.Base(dir)
	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

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

	for _, clojurePkg := range pkgs {
		key := clojurePkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    clojurePkg.Name,
			Version: clojurePkg.Version,
		}
		g.Modules[clojurePkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: clojurePkg.Name,
			Name:       clojurePkg.Name,
			Module:     mod,
		}

		// Apply import-level capabilities for known Clojure packages.
		applyClojureImportCaps(clojurePkg, pkg)

		g.Packages[clojurePkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[clojurePkg.Name] = clojurePkg.Dependencies

		if clojurePkg.Direct {
			rootEdges = append(rootEdges, clojurePkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyClojureImportCaps applies import-level capabilities by matching the
// artifact name against known Clojure patterns.
func applyClojureImportCaps(clojurePkg ClojurePackage, pkg *graph.Package) {
	// Try the name as-is plus common normalisation variants.
	candidates := []string{clojurePkg.Name}

	// group/artifact → try "group", "artifact", and "group-artifact".
	if slash := strings.IndexByte(clojurePkg.Name, '/'); slash > 0 {
		group := clojurePkg.Name[:slash]
		artifact := clojurePkg.Name[slash+1:]
		candidates = append(candidates, group, artifact, group+"-"+artifact)
	}

	for _, candidate := range candidates {
		if importCaps, ok := clojurePatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    clojurePkg.Name + "@" + clojurePkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Clojure dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildClojureFunctionIRGraph(g)
}

// buildClojureFunctionIRGraph converts packages into a function-level IRGraph.
func buildClojureFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		var files []string
		for _, pat := range []string{"*.clj", "*.cljs", "*.cljc"} {
			fs, _ := filepath.Glob(filepath.Join(pkg.Dir, pat))
			files = append(files, fs...)
		}

		if len(files) == 0 {
			continue
		}

		var names []string
		for _, f := range files {
			names = append(names, filepath.Base(f))
		}

		funcs, edges, _ := DetectFunctions(pkg.Dir, names)
		for k, fc := range funcs {
			irGraph.Functions[k] = fc
		}
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
