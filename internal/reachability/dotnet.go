package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	dotnet "github.com/1homsi/gorisk/internal/adapters/dotnet"
)

// reDotnetUsing matches C# and VB using/Imports statements.
// Group 1 = namespace name (e.g. "System.Net.Http").
var reDotnetUsing = regexp.MustCompile(`^\s*using\s+([\w.]+)\s*;`)

// DotnetAnalyzer implements Analyzer using C#/VB namespace import analysis.
type DotnetAnalyzer struct{}

func (DotnetAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeDotnet(dir, "")
}

func (DotnetAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeDotnet(dir, entryFile)
}

func analyzeDotnet(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &dotnet.Adapter{}
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
		imported = collectDotnetFileImports(entryPath)
	} else {
		imported = collectDotnetProjectImports(dir)
	}

	// Map namespace prefixes to NuGet package names using the packages in the graph.
	// A namespace "Newtonsoft.Json.Linq" maps to the package "Newtonsoft.Json"
	// by taking the first two dot-separated segments (lowercased).
	pkgNames := make(map[string]bool)
	for pkgName := range g.Packages {
		pkgNames[strings.ToLower(pkgName)] = true
	}

	// Resolve imported namespaces to package names.
	resolvedImports := make(map[string]bool)
	for ns := range imported {
		pkgName := namespaceToPackage(ns, pkgNames)
		if pkgName != "" {
			resolvedImports[pkgName] = true
		}
	}

	reachable := resolveReachable(resolvedImports, g.Edges)

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
			Reachable:     reachable[pkgName] || reachable[strings.ToLower(pkgName)],
		})
	}

	return reports, nil
}

// collectDotnetFileImports scans a single .cs or .vb file for using/Imports statements.
func collectDotnetFileImports(path string) map[string]bool {
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
		if m := reDotnetUsing.FindStringSubmatch(line); m != nil {
			imported[m[1]] = true
		}
	}
	return imported
}

// collectDotnetProjectImports scans all .cs and .vb source files in dir,
// skipping bin, obj, .vs, and packages directories.
func collectDotnetProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"bin":      true,
		"obj":      true,
		".vs":      true,
		"packages": true,
	}

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".cs" && ext != ".vb" {
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
			if m := reDotnetUsing.FindStringSubmatch(line); m != nil {
				imported[m[1]] = true
			}
		}
		return nil
	})

	return imported
}

// namespaceToPackage maps a C# namespace to a NuGet package name.
// It uses longest-prefix matching against the known package names in the graph.
// Fallback: take the first two dot-separated segments lowercased.
func namespaceToPackage(ns string, pkgNames map[string]bool) string {
	parts := strings.Split(ns, ".")
	// Try longest prefix first.
	for i := len(parts); i >= 1; i-- {
		candidate := strings.Join(parts[:i], ".")
		lower := strings.ToLower(candidate)
		if pkgNames[lower] {
			return lower
		}
	}
	// Fallback: first two segments.
	if len(parts) >= 2 {
		return strings.ToLower(parts[0] + "." + parts[1])
	}
	return strings.ToLower(ns)
}
