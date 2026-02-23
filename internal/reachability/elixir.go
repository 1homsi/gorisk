package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	elixir "github.com/1homsi/gorisk/internal/adapters/elixir"
)

// reElixirImport matches use/import/alias statements in Elixir source files.
// Group 1 = the module name, e.g. "Phoenix.Controller".
var reElixirImport = regexp.MustCompile(`(?:use|import|alias)\s+([A-Z][A-Za-z0-9.]+)`)

// ElixirAnalyzer implements Analyzer using Elixir use/import/alias analysis.
type ElixirAnalyzer struct{}

func (ElixirAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeElixir(dir, "")
}

func (ElixirAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeElixir(dir, entryFile)
}

func analyzeElixir(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &elixir.Adapter{}
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
		imported = collectElixirFileImports(entryPath)
	} else {
		imported = collectElixirProjectImports(dir)
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

// collectElixirFileImports scans a single .ex/.exs file for use/import/alias
// statements and returns the corresponding mix package names.
func collectElixirFileImports(path string) map[string]bool {
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
		for _, m := range reElixirImport.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				pkg := elixirModuleToPackage(m[1])
				if pkg != "" {
					imported[pkg] = true
				}
			}
		}
	}
	return imported
}

// collectElixirProjectImports scans all .ex/.exs files in dir, skipping
// _build, deps, and .elixir_ls directories.
func collectElixirProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"_build":     true,
		"deps":       true,
		".elixir_ls": true,
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
		if ext != ".ex" && ext != ".exs" {
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
			for _, m := range reElixirImport.FindAllStringSubmatch(line, -1) {
				if len(m) > 1 {
					pkg := elixirModuleToPackage(m[1])
					if pkg != "" {
						imported[pkg] = true
					}
				}
			}
		}
		return nil
	})

	return imported
}

// elixirModuleToPackage converts an Elixir module name to a mix package name.
// Elixir modules use PascalCase with dots; mix packages are snake_case.
// e.g. "Phoenix.Controller" → "phoenix", "Ecto.Repo" → "ecto"
func elixirModuleToPackage(moduleName string) string {
	// Take only the first segment (before any dot).
	first := moduleName
	if idx := strings.Index(moduleName, "."); idx >= 0 {
		first = moduleName[:idx]
	}
	if first == "" {
		return ""
	}
	return strings.ToLower(first)
}
