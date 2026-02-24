package swift

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Swift/SPM projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "swift" }

// Load parses the Swift dependency lockfile in dir, detects capabilities from
// .swift source files, and returns a *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Swift project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .swift files.
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

	for _, swiftPkg := range pkgs {
		key := swiftPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    swiftPkg.Name,
			Version: swiftPkg.Version,
		}
		g.Modules[swiftPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: swiftPkg.Name,
			Name:       swiftPkg.Name,
			Module:     mod,
		}

		// Detect capabilities from installed package source (if available).
		if pkgDir := mod.Dir; pkgDir != "" {
			if _, statErr := os.Stat(pkgDir); statErr == nil {
				pkg.Capabilities = Detect(pkgDir)
			}
		}

		// Apply import-level capabilities for known Swift packages.
		applySwiftImportCaps(swiftPkg, pkg)

		g.Packages[swiftPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[swiftPkg.Name] = swiftPkg.Dependencies

		if swiftPkg.Direct {
			rootEdges = append(rootEdges, swiftPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applySwiftImportCaps applies import-level capabilities by matching the
// package name against known Swift patterns (with normalisation variants).
func applySwiftImportCaps(swiftPkg SwiftPackage, pkg *graph.Package) {
	candidates := []string{
		swiftPkg.Name,
		strings.ToLower(swiftPkg.Name),
		strings.ReplaceAll(swiftPkg.Name, "-", ""),
		strings.ReplaceAll(strings.ToLower(swiftPkg.Name), "-", ""),
	}
	for _, candidate := range candidates {
		if importCaps, ok := swiftPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    swiftPkg.Name + "@" + swiftPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Swift dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildSwiftFunctionIRGraph(g)
}

// buildSwiftFunctionIRGraph converts packages into a function-level IRGraph
// by recursively parsing .swift source files in each package directory.
func buildSwiftFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
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
				n := d.Name()
				if n == ".build" || n == "DerivedData" || (len(n) > 0 && n[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.ToLower(filepath.Ext(path)) == ".swift" {
				if rel, e := filepath.Rel(pkg.Dir, path); e == nil {
					relFiles = append(relFiles, rel)
				}
			}
			return nil
		})
		if len(relFiles) == 0 {
			continue
		}

		funcs, edges, _ := DetectFunctions(pkg.Dir, pkg.ImportPath, relFiles)
		for k, fc := range funcs {
			irGraph.Functions[k] = fc
		}
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
