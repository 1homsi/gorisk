package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	clojureadapter "github.com/1homsi/gorisk/internal/adapters/clojure"
)

// reClojureRequire matches :require namespace references in Clojure source:
//
//	(:require [namespace.sub :as alias])
var reClojureRequire = regexp.MustCompile(`:require\s+\[([a-zA-Z][a-zA-Z0-9._\-]*)`)

// reClojureNs matches Clojure namespace declarations:
//
//	(ns namespace.name
var reClojureNs = regexp.MustCompile(`ns\s+([a-zA-Z][a-zA-Z0-9._\-]*)`)

// ClojureAnalyzer implements Analyzer using Clojure namespace import analysis.
type ClojureAnalyzer struct{}

func (ClojureAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeClojure(dir, "")
}

func (ClojureAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeClojure(dir, entryFile)
}

// analyzeClojure scans the project's Clojure source files to determine which
// installed packages are actually used ("reachable").
func analyzeClojure(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &clojureadapter.Adapter{}
	g, err := adapter.Load(dir)
	if err != nil {
		return nil, err
	}

	var imported map[string]bool
	if entryFile != "" {
		entryPath := entryFile
		if !filepath.IsAbs(entryFile) {
			entryPath = filepath.Join(dir, entryFile)
		}
		imported = collectClojureFileImports(entryPath)
	} else {
		imported = collectClojureProjectImports(dir)
	}

	reachable := resolveReachable(imported, g.Edges)

	seen := make(map[string]bool)
	var reports []ReachabilityReport

	for pkgName, pkg := range g.Packages {
		if pkg.Module != nil && pkg.Module.Main {
			continue
		}
		if pkg.Capabilities.Score == 0 {
			continue
		}
		if seen[pkgName] {
			continue
		}
		seen[pkgName] = true

		reports = append(reports, ReachabilityReport{
			Package:       pkgName,
			ReachableCaps: pkg.Capabilities,
			Reachable:     reachable[pkgName],
		})
	}

	return reports, nil
}

// collectClojureFileImports scans a single Clojure file for namespace imports.
func collectClojureFileImports(path string) map[string]bool {
	imported := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		return imported
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		collectClojureImportsFromLine(line, imported)
	}
	return imported
}

// collectClojureProjectImports scans all .clj, .cljs, .cljc files in a
// directory, excluding target/ and .cljs_node_repl/.
func collectClojureProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"target":          true,
		".cljs_node_repl": true,
		".git":            true,
	}

	clojureExts := map[string]bool{
		".clj":  true,
		".cljs": true,
		".cljc": true,
	}

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !clojureExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			collectClojureImportsFromLine(line, imported)
		}
		return nil
	})

	return imported
}

// collectClojureImportsFromLine extracts namespace roots from a single line
// and adds them to the imported map. It extracts both :require namespace
// references and ns declarations, mapping the namespace root to a package name.
func collectClojureImportsFromLine(line string, imported map[string]bool) {
	for _, m := range reClojureRequire.FindAllStringSubmatch(line, -1) {
		ns := m[1]
		// Extract the namespace root (first segment before ".").
		root := namespaceRoot(ns)
		if root != "" {
			imported[root] = true
			// Also add the full namespace for direct matching.
			imported[ns] = true
		}
	}
	for _, m := range reClojureNs.FindAllStringSubmatch(line, -1) {
		ns := m[1]
		root := namespaceRoot(ns)
		if root != "" {
			imported[root] = true
		}
	}
}

// namespaceRoot returns the first dot-separated segment of a Clojure namespace.
func namespaceRoot(ns string) string {
	if idx := strings.IndexByte(ns, '.'); idx > 0 {
		return ns[:idx]
	}
	return ns
}
