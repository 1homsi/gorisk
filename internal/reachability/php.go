package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	php "github.com/1homsi/gorisk/internal/adapters/php"
)

// reUseStatement matches PHP use statements: use Vendor\Package\ClassName;
var reUseStatement = regexp.MustCompile(`^\s*use\s+([\\A-Za-z0-9_]+)`)

// PHPAnalyzer implements Analyzer using PHP use-statement import analysis.
type PHPAnalyzer struct{}

func (PHPAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzePHP(dir, "")
}

func (PHPAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzePHP(dir, entryFile)
}

// analyzePHP scans the project's own PHP source files to determine which
// installed Composer packages are actually used ("reachable").
func analyzePHP(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &php.Adapter{}
	g, err := adapter.Load(dir)
	if err != nil {
		return nil, err
	}

	// Collect all use statements / requires from project source files.
	var imported map[string]bool
	if entryFile != "" {
		entryPath := entryFile
		if !filepath.IsAbs(entryFile) {
			entryPath = filepath.Join(dir, entryFile)
		}
		imported = collectPHPFileImports(entryPath)
	} else {
		imported = collectPHPProjectImports(dir)
	}

	// Resolve transitive reachability through the dependency graph.
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

// collectPHPFileImports scans a single PHP file for use statements and
// returns Composer package names that appear to be imported.
func collectPHPFileImports(path string) map[string]bool {
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
		if m := reUseStatement.FindStringSubmatch(line); m != nil {
			pkg := composerPackageFromNamespace(m[1])
			if pkg != "" {
				imported[pkg] = true
			}
		}
	}
	return imported
}

// collectPHPProjectImports scans all PHP source files in a directory (excluding vendor/).
func collectPHPProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".php" {
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
			if m := reUseStatement.FindStringSubmatch(line); m != nil {
				pkg := composerPackageFromNamespace(m[1])
				if pkg != "" {
					imported[pkg] = true
				}
			}
		}
		return nil
	})

	return imported
}

// composerPackageFromNamespace converts a PHP namespace to a Composer package name.
// e.g. "GuzzleHttp\Client" → "guzzlehttp/guzzle"
// This is a best-effort heuristic: vendor\package pattern maps to vendor/package.
func composerPackageFromNamespace(ns string) string {
	// Normalise backslashes
	ns = strings.ReplaceAll(ns, `\\`, `\`)
	parts := strings.SplitN(ns, `\`, 3)
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[0]) + "/" + strings.ToLower(parts[1])
}
