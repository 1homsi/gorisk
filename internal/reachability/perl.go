package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	perladapter "github.com/1homsi/gorisk/internal/adapters/perl"
)

// rePerlUse matches Perl use statements:
//
//	use LWP::UserAgent;
//	use strict;
var rePerlUse = regexp.MustCompile(`^use\s+([A-Za-z][A-Za-z0-9:]*)`)

// rePerlRequire matches Perl require statements:
//
//	require LWP::UserAgent;
//	require 'LWP/UserAgent.pm';
var rePerlRequire = regexp.MustCompile(`^require\s+['"]?([A-Za-z][A-Za-z0-9:/]*)`)

// PerlAnalyzer implements Analyzer using Perl use/require import analysis.
type PerlAnalyzer struct{}

func (PerlAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzePerl(dir, "")
}

func (PerlAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzePerl(dir, entryFile)
}

// analyzePerl scans the project's .pl, .pm, and .t files to determine which
// installed packages are actually used ("reachable").
func analyzePerl(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &perladapter.Adapter{}
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
		imported = collectPerlFileImports(entryPath)
	} else {
		imported = collectPerlProjectImports(dir)
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

		// Match package by direct name or converted dist name.
		pkgReachable := reachable[pkgName]
		if !pkgReachable {
			pkgReachable = reachable[perlModuleToDist(pkgName)]
		}

		reports = append(reports, ReachabilityReport{
			Package:       pkgName,
			ReachableCaps: pkg.Capabilities,
			Reachable:     pkgReachable,
		})
	}

	return reports, nil
}

// collectPerlFileImports scans a single Perl file for use/require statements.
func collectPerlFileImports(path string) map[string]bool {
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
		collectPerlImportsFromLine(line, imported)
	}
	return imported
}

// collectPerlProjectImports scans all .pl, .pm, and .t files in a directory,
// excluding blib/ and local/.
func collectPerlProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"blib":  true,
		"local": true,
		".git":  true,
	}

	perlExts := map[string]bool{
		".pl": true,
		".pm": true,
		".t":  true,
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
		if !perlExts[strings.ToLower(filepath.Ext(path))] {
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
			collectPerlImportsFromLine(line, imported)
		}
		return nil
	})

	return imported
}

// collectPerlImportsFromLine extracts Perl module names from a single line and
// adds both the module name and its dist-name equivalent to the imported map.
func collectPerlImportsFromLine(line string, imported map[string]bool) {
	if m := rePerlUse.FindStringSubmatch(line); m != nil {
		name := m[1]
		imported[name] = true
		imported[perlModuleToDist(name)] = true
	}
	if m := rePerlRequire.FindStringSubmatch(line); m != nil {
		name := m[1]
		// Convert path-style (LWP/UserAgent) to module-style (LWP::UserAgent).
		name = strings.ReplaceAll(name, "/", "::")
		name = strings.TrimSuffix(name, ".pm")
		imported[name] = true
		imported[perlModuleToDist(name)] = true
	}
}

// perlModuleToDist converts a Perl module name to a CPAN distribution name.
// e.g. "LWP::UserAgent" → "lwp-useragent", "Moose" → "moose"
func perlModuleToDist(module string) string {
	return strings.ToLower(strings.ReplaceAll(module, "::", "-"))
}
