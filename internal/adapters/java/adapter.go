// Package java implements a gorisk analyzer for Java projects.
// It supports Maven pom.xml and Gradle gradle.lockfile / build.gradle.
package java

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the analyzer.Analyzer interface for Java projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "java" }

// Load parses the Java dependency lockfile in dir, detects capabilities from
// .java source files, and returns a *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the Java project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .java files.
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

	for _, javaPkg := range pkgs {
		key := javaPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    javaPkg.Name,
			Version: javaPkg.Version,
			Dir:     javaPkg.Dir,
		}
		g.Modules[javaPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: javaPkg.Name,
			Name:       javaPkg.Name,
			Module:     mod,
			Dir:        javaPkg.Dir,
		}

		// Detect capabilities from installed package source (if available).
		if javaPkg.Dir != "" {
			if _, statErr := os.Stat(javaPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(javaPkg.Dir)
			}
		}

		// Apply import-level capabilities for known Java packages via groupID/artifactID
		// or any prefix segment of the groupID (e.g. "com.google.guava" → "com.google.guava").
		applyImportCaps(javaPkg, pkg)

		g.Packages[javaPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[javaPkg.Name] = javaPkg.Dependencies

		if javaPkg.Direct {
			rootEdges = append(rootEdges, javaPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyImportCaps applies import-level capabilities from the pattern set to pkg
// by matching the package's groupID against known Java import prefixes.
func applyImportCaps(javaPkg JavaPackage, pkg *graph.Package) {
	// Build candidate keys from the groupID using progressively shorter prefixes.
	parts := make([]string, 0, 4)
	seg := javaPkg.GroupID
	for seg != "" {
		parts = append(parts, seg)
		dot := len(seg)
		idx := -1
		// Find last dot to shorten.
		for i := dot - 1; i >= 0; i-- {
			if seg[i] == '.' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		seg = seg[:idx]
	}

	for _, candidate := range parts {
		if importCaps, ok := javaPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       "lockfile",
					Context:    javaPkg.Name + "@" + javaPkg.Version,
					Via:        "import",
					Confidence: 0.90,
				})
			}
			// Use the most specific match only.
			return
		}
	}
}

// BuildIRGraph builds a function-level IR graph for a Java dependency graph.
func BuildIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	return buildJavaFunctionIRGraph(g)
}

// buildJavaFunctionIRGraph converts packages into a function-level IRGraph.
// Recursively walks each package directory for .java files.
func buildJavaFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
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
				if n == "target" || n == "build" || n == ".gradle" || (len(n) > 0 && n[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.ToLower(filepath.Ext(path)) == ".java" {
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
