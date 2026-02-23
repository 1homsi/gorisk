package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	rubyadapter "github.com/1homsi/gorisk/internal/adapters/ruby"
)

// reRequireRuby matches `require 'gemname'` or `require "gemname"` statements.
// Excludes relative paths (starting with . or /) and standard library names
// that contain path separators.
var reRequireRuby = regexp.MustCompile(`require\s+['"]([^'"./][^'"]*)['"]`)

// RubyAnalyzer implements Analyzer using Ruby require analysis.
type RubyAnalyzer struct{}

func (RubyAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeRuby(dir, "")
}

func (RubyAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeRuby(dir, entryFile)
}

// analyzeRuby scans the project's .rb files to determine which installed gems
// are actually used ("reachable").
func analyzeRuby(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &rubyadapter.Adapter{}
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
		imported = collectRubyFileImports(entryPath)
	} else {
		imported = collectRubyProjectImports(dir)
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

// collectRubyFileImports scans a single .rb file for require statements.
func collectRubyFileImports(path string) map[string]bool {
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
		for _, m := range reRequireRuby.FindAllStringSubmatch(line, -1) {
			imported[m[1]] = true
		}
	}
	return imported
}

// collectRubyProjectImports scans all .rb source files in a directory,
// excluding common build/vendor directories.
func collectRubyProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"vendor": true, ".bundle": true, ".git": true,
		"tmp": true, "log": true,
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
		if strings.ToLower(filepath.Ext(path)) != ".rb" {
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
			for _, m := range reRequireRuby.FindAllStringSubmatch(line, -1) {
				imported[m[1]] = true
			}
		}
		return nil
	})

	return imported
}
