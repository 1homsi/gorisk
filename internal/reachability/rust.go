package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	rustadapter "github.com/1homsi/gorisk/internal/adapters/rust"
)

// reUseCrate matches the crate name from Rust use/extern crate statements.
// Handles: `use tokio::runtime::Runtime;`, `extern crate serde;`
var reUseCrate = regexp.MustCompile(`^(?:use|extern\s+crate)\s+([a-zA-Z0-9_]+)`)

// RustAnalyzer implements Analyzer using Rust use/extern-crate analysis.
type RustAnalyzer struct{}

func (RustAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeRust(dir, "")
}

func (RustAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeRust(dir, entryFile)
}

// analyzeRust scans the project's .rs files to determine which installed
// crates are actually used ("reachable").
func analyzeRust(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &rustadapter.Adapter{}
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
		imported = collectRustFileImports(entryPath)
	} else {
		imported = collectRustProjectImports(dir)
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

// collectRustFileImports scans a single .rs file for use/extern crate statements.
func collectRustFileImports(path string) map[string]bool {
	imported := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		return imported
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if m := reUseCrate.FindStringSubmatch(line); m != nil {
			// Rust crate names use underscores but Cargo.lock uses hyphens — normalise.
			imported[strings.ReplaceAll(m[1], "_", "-")] = true
			imported[m[1]] = true
		}
	}
	return imported
}

// collectRustProjectImports scans all .rs source files in a directory,
// excluding common build-output directories.
func collectRustProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"target": true, ".git": true,
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
		if strings.ToLower(filepath.Ext(path)) != ".rs" {
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
			line := strings.TrimSpace(scanner.Text())
			if m := reUseCrate.FindStringSubmatch(line); m != nil {
				imported[strings.ReplaceAll(m[1], "_", "-")] = true
				imported[m[1]] = true
			}
		}
		return nil
	})

	return imported
}
