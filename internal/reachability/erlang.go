package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	erlangadapter "github.com/1homsi/gorisk/internal/adapters/erlang"
)

// reErlangIncludeLib matches -include_lib("libname/...") directives:
//
//	-include_lib("cowboy/include/cowboy.hrl").
var reErlangIncludeLib = regexp.MustCompile(`-include_lib\("([^/]+)/`)

// reErlangModuleCall matches module:function call patterns:
//
//	cowboy:start_clear(...)
var reErlangModuleCall = regexp.MustCompile(`^\s*([a-z][a-z0-9_]*):`)

// ErlangAnalyzer implements Analyzer using Erlang include/call analysis.
type ErlangAnalyzer struct{}

func (ErlangAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeErlang(dir, "")
}

func (ErlangAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeErlang(dir, entryFile)
}

// analyzeErlang scans the project's .erl and .hrl source files to determine
// which installed packages are actually used ("reachable").
func analyzeErlang(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &erlangadapter.Adapter{}
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
		imported = collectErlangFileImports(entryPath)
	} else {
		imported = collectErlangProjectImports(dir)
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

// collectErlangFileImports scans a single .erl or .hrl file for library references.
func collectErlangFileImports(path string) map[string]bool {
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
		collectErlangImportsFromLine(line, imported)
	}
	return imported
}

// collectErlangProjectImports scans all .erl and .hrl files in a directory,
// excluding _build/ and ebin/.
func collectErlangProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"_build": true,
		"ebin":   true,
		".git":   true,
	}

	erlangExts := map[string]bool{
		".erl": true,
		".hrl": true,
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
		if !erlangExts[strings.ToLower(filepath.Ext(path))] {
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
			collectErlangImportsFromLine(line, imported)
		}
		return nil
	})

	return imported
}

// collectErlangImportsFromLine extracts library names from a single line.
// Primary signal: -include_lib("libname/..."); secondary: module: call patterns.
func collectErlangImportsFromLine(line string, imported map[string]bool) {
	// Primary: -include_lib directives give definitive library names.
	for _, m := range reErlangIncludeLib.FindAllStringSubmatch(line, -1) {
		imported[m[1]] = true
	}
	// Secondary: module:function calls.
	if m := reErlangModuleCall.FindStringSubmatch(line); m != nil {
		imported[m[1]] = true
	}
}
