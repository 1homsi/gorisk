package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	radapter "github.com/1homsi/gorisk/internal/adapters/r"
)

// reRLibrary matches R library/require calls:
//
//	library(ggplot2)
//	require("dplyr")
var reRLibrary = regexp.MustCompile(`(?:library|require)\s*\(\s*["']?([A-Za-z][A-Za-z0-9._]*)`)

// reRNamespace matches R package::function calls:
//
//	ggplot2::ggplot(...)
var reRNamespace = regexp.MustCompile(`([A-Za-z][A-Za-z0-9._]+)::`)

// RAnalyzer implements Analyzer using R library/require/namespace analysis.
type RAnalyzer struct{}

func (RAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeR(dir, "")
}

func (RAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeR(dir, entryFile)
}

// analyzeR scans the project's .R and .r files to determine which
// installed packages are actually used ("reachable").
func analyzeR(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &radapter.Adapter{}
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
		imported = collectRFileImports(entryPath)
	} else {
		imported = collectRProjectImports(dir)
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

// collectRFileImports scans a single R file for library/require/namespace references.
func collectRFileImports(path string) map[string]bool {
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
		collectRImportsFromLine(line, imported)
	}
	return imported
}

// collectRProjectImports scans all .R and .r files in a directory,
// excluding renv/.
func collectRProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"renv": true,
		".git": true,
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
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".r" {
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
			collectRImportsFromLine(line, imported)
		}
		return nil
	})

	return imported
}

// collectRImportsFromLine extracts R package names from a single line.
func collectRImportsFromLine(line string, imported map[string]bool) {
	for _, m := range reRLibrary.FindAllStringSubmatch(line, -1) {
		imported[m[1]] = true
	}
	for _, m := range reRNamespace.FindAllStringSubmatch(line, -1) {
		imported[m[1]] = true
	}
}
