package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	pythonadapter "github.com/1homsi/gorisk/internal/adapters/python"
)

// reImportPy matches the top-level module name from Python import statements.
// Handles: `import requests`, `from requests import Session`
var reImportPy = regexp.MustCompile(`^(?:import|from)\s+([a-zA-Z0-9_]+)`)

// PythonAnalyzer implements Analyzer using Python import analysis.
type PythonAnalyzer struct{}

func (PythonAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzePython(dir, "")
}

func (PythonAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzePython(dir, entryFile)
}

// analyzePython scans the project's .py files to determine which installed
// packages are actually used ("reachable").
func analyzePython(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &pythonadapter.Adapter{}
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
		imported = collectPythonFileImports(entryPath)
	} else {
		imported = collectPythonProjectImports(dir)
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

// collectPythonFileImports scans a single .py file for import statements.
func collectPythonFileImports(path string) map[string]bool {
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
		if m := reImportPy.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			imported[m[1]] = true
		}
	}
	return imported
}

// collectPythonProjectImports scans all .py source files in a directory,
// excluding common virtual-environment and cache directories.
func collectPythonProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"venv": true, ".venv": true, "env": true, ".env": true,
		"__pycache__": true, ".git": true, "site-packages": true,
		"dist": true, "build": true, ".tox": true,
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
		if strings.ToLower(filepath.Ext(path)) != ".py" {
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
			if m := reImportPy.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				imported[m[1]] = true
			}
		}
		return nil
	})

	return imported
}
