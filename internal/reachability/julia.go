package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	juliaadapter "github.com/1homsi/gorisk/internal/adapters/julia"
)

// reJuliaImport matches Julia using/import statements:
//
//	using Plots
//	import DataFrames
//	using LinearAlgebra, Statistics
var reJuliaImport = regexp.MustCompile(`(?:using|import)\s+([A-Za-z][A-Za-z0-9_]*)`)

// JuliaAnalyzer implements Analyzer using Julia using/import analysis.
type JuliaAnalyzer struct{}

func (JuliaAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeJulia(dir, "")
}

func (JuliaAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeJulia(dir, entryFile)
}

// analyzeJulia scans the project's .jl source files to determine which
// installed packages are actually used ("reachable").
func analyzeJulia(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &juliaadapter.Adapter{}
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
		imported = collectJuliaFileImports(entryPath)
	} else {
		imported = collectJuliaProjectImports(dir)
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

		// Match package by direct name or lowercase variant.
		pkgReachable := reachable[pkgName]
		if !pkgReachable {
			pkgReachable = reachable[strings.ToLower(pkgName)]
		}

		reports = append(reports, ReachabilityReport{
			Package:       pkgName,
			ReachableCaps: pkg.Capabilities,
			Reachable:     pkgReachable,
		})
	}

	return reports, nil
}

// collectJuliaFileImports scans a single .jl file for using/import statements.
func collectJuliaFileImports(path string) map[string]bool {
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
		for _, m := range reJuliaImport.FindAllStringSubmatch(line, -1) {
			name := m[1]
			imported[name] = true
			imported[strings.ToLower(name)] = true
		}
	}
	return imported
}

// collectJuliaProjectImports scans all .jl files in a directory,
// excluding .git/.
func collectJuliaProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".jl" {
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
			for _, m := range reJuliaImport.FindAllStringSubmatch(line, -1) {
				name := m[1]
				imported[name] = true
				imported[strings.ToLower(name)] = true
			}
		}
		return nil
	})

	return imported
}
