package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	dart "github.com/1homsi/gorisk/internal/adapters/dart"
)

// reDartImport matches Dart package import statements.
// Group 1 = package name (before the first slash or quote).
var reDartImport = regexp.MustCompile(`import\s+['"]package:([^/'"]+)`)

// DartAnalyzer implements Analyzer using Dart package import analysis.
type DartAnalyzer struct{}

func (DartAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeDart(dir, "")
}

func (DartAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeDart(dir, entryFile)
}

func analyzeDart(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &dart.Adapter{}
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
		imported = collectDartFileImports(entryPath)
	} else {
		imported = collectDartProjectImports(dir)
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

// collectDartFileImports scans a single .dart file for package import statements.
func collectDartFileImports(path string) map[string]bool {
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
		for _, m := range reDartImport.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				imported[m[1]] = true
			}
		}
	}
	return imported
}

// collectDartProjectImports scans all .dart files in dir.
func collectDartProjectImports(dir string) map[string]bool {
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
		if strings.ToLower(filepath.Ext(path)) != ".dart" {
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
			for _, m := range reDartImport.FindAllStringSubmatch(line, -1) {
				if len(m) > 1 {
					imported[m[1]] = true
				}
			}
		}
		return nil
	})

	return imported
}
