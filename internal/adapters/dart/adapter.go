package dart

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Dart/Flutter projects.
type Adapter struct{}

func (Adapter) Name() string { return "dart" }

// Load parses the Dart dependency lockfile in dir, detects capabilities from
// .dart source files, and returns a *graph.DependencyGraph.
func (Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Dart/Flutter project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .dart files.
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

	for _, dartPkg := range pkgs {
		key := dartPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    dartPkg.Name,
			Version: dartPkg.Version,
		}
		g.Modules[dartPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: dartPkg.Name,
			Name:       dartPkg.Name,
			Module:     mod,
		}

		// Detect capabilities from installed package source (if available).
		if pkgDir := mod.Dir; pkgDir != "" {
			if _, statErr := os.Stat(pkgDir); statErr == nil {
				pkg.Capabilities = Detect(pkgDir)
			}
		}

		// Apply import-level capabilities for known Dart packages.
		applyDartImportCaps(dartPkg, pkg)

		g.Packages[dartPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[dartPkg.Name] = dartPkg.Dependencies

		if dartPkg.Direct {
			rootEdges = append(rootEdges, dartPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyDartImportCaps applies import-level capabilities by matching the package
// name against known Dart patterns.
func applyDartImportCaps(dartPkg DartPackage, pkg *graph.Package) {
	if importCaps, ok := dartPatterns.Imports[dartPkg.Name]; ok {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    dartPkg.Name + "@" + dartPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Dart dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildDartFunctionIRGraph(g)
}

// buildDartFunctionIRGraph converts packages into a function-level IRGraph
// by recursively parsing .dart source files in each package directory.
func buildDartFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
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
				if n == ".dart_tool" || n == "build" || (len(n) > 0 && n[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.ToLower(filepath.Ext(path)) == ".dart" {
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
