package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	ocamladapter "github.com/1homsi/gorisk/internal/adapters/ocaml"
)

// reOCamlOpen matches OCaml open statements:
//
//	open Lwt
//	open Cohttp_lwt_unix
var reOCamlOpen = regexp.MustCompile(`^\s*open\s+([A-Z][A-Za-z0-9_]*)`)

// reOCamlModuleAlias matches OCaml module alias declarations:
//
//	module Http = Cohttp_lwt_unix
var reOCamlModuleAlias = regexp.MustCompile(`^\s*module\s+\w+\s*=\s*([A-Z][A-Za-z0-9_.]*)`)

// OCamlAnalyzer implements Analyzer using OCaml open/module import analysis.
type OCamlAnalyzer struct{}

func (OCamlAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeOCaml(dir, "")
}

func (OCamlAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeOCaml(dir, entryFile)
}

// analyzeOCaml scans the project's .ml and .mli files to determine which
// installed packages are actually used ("reachable").
func analyzeOCaml(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &ocamladapter.Adapter{}
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
		imported = collectOCamlFileImports(entryPath)
	} else {
		imported = collectOCamlProjectImports(dir)
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

// collectOCamlFileImports scans a single .ml or .mli file for open/module references.
func collectOCamlFileImports(path string) map[string]bool {
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
		collectOCamlImportsFromLine(line, imported)
	}
	return imported
}

// collectOCamlProjectImports scans all .ml and .mli files in a directory,
// excluding _build/ and .merlin.
func collectOCamlProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"_build": true,
		".git":   true,
	}

	ocamlExts := map[string]bool{
		".ml":  true,
		".mli": true,
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
		// Skip .merlin files (they are config, not source).
		if d.Name() == ".merlin" {
			return nil
		}
		if !ocamlExts[strings.ToLower(filepath.Ext(path))] {
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
			collectOCamlImportsFromLine(line, imported)
		}
		return nil
	})

	return imported
}

// collectOCamlImportsFromLine extracts OCaml module names and converts them
// to lowercase opam package names.
func collectOCamlImportsFromLine(line string, imported map[string]bool) {
	if m := reOCamlOpen.FindStringSubmatch(line); m != nil {
		// Convert CamelCase module name to lowercase opam package name.
		imported[ocamlModuleToPackage(m[1])] = true
	}
	if m := reOCamlModuleAlias.FindStringSubmatch(line); m != nil {
		// Take the first component of a dotted module path.
		mod := m[1]
		if idx := strings.IndexByte(mod, '.'); idx > 0 {
			mod = mod[:idx]
		}
		imported[ocamlModuleToPackage(mod)] = true
	}
}

// ocamlModuleToPackage converts an OCaml module name (CamelCase) to the
// lowercase opam package name convention (e.g. CohttpLwtUnix → cohttp-lwt-unix).
func ocamlModuleToPackage(module string) string {
	// Simple heuristic: lowercase the whole name and replace _ with -.
	return strings.ToLower(strings.ReplaceAll(module, "_", "-"))
}
