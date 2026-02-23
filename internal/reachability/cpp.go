package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	cppadapter "github.com/1homsi/gorisk/internal/adapters/cpp"
	"github.com/1homsi/gorisk/internal/graph"
)

// reCppInclude matches C/C++ #include directives.
var reCppInclude = regexp.MustCompile(`#include\s+[<"]([^>"]+)[>"]`)

// CppAnalyzer implements Analyzer using C/C++ #include directive analysis.
type CppAnalyzer struct{}

func (CppAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeCpp(dir, "")
}

func (CppAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeCpp(dir, entryFile)
}

// analyzeCpp scans the project's C/C++ source files to determine which
// installed packages are actually used ("reachable").
func analyzeCpp(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &cppadapter.Adapter{}
	g, err := adapter.Load(dir)
	if err != nil {
		return nil, err
	}

	// Build a lowercase name → original name lookup map.
	pkgMap := buildCppPkgMap(g.Packages)

	var imported map[string]bool
	if entryFile != "" {
		entryPath := entryFile
		if !filepath.IsAbs(entryFile) {
			entryPath = filepath.Join(dir, entryFile)
		}
		imported = collectCppFileImports(entryPath, pkgMap)
	} else {
		imported = collectCppProjectImports(dir, pkgMap)
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

// buildCppPkgMap builds a lowercase name → original name map from the package graph.
func buildCppPkgMap(packages map[string]*graph.Package) map[string]string {
	m := make(map[string]string, len(packages))
	for name := range packages {
		m[strings.ToLower(name)] = name
	}
	return m
}

// collectCppFileImports scans a single C/C++ file for #include directives
// and matches them against known package names.
func collectCppFileImports(path string, pkgMap map[string]string) map[string]bool {
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
		if m := reCppInclude.FindStringSubmatch(line); m != nil {
			base := filepath.Base(strings.TrimSuffix(m[1], filepath.Ext(m[1])))
			lower := strings.ToLower(base)
			if pkgName, ok := pkgMap[lower]; ok {
				imported[pkgName] = true
			}
		}
	}
	return imported
}

// collectCppProjectImports scans all C/C++ source files in a directory
// (excluding build/, cmake-build-debug/, cmake-build-release/, .cache/).
func collectCppProjectImports(dir string, pkgMap map[string]string) map[string]bool {
	imported := make(map[string]bool)

	cppExts := map[string]bool{
		".c": true, ".cpp": true, ".cc": true,
		".cxx": true, ".h": true, ".hpp": true,
	}

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			switch name {
			case "build", "cmake-build-debug", "cmake-build-release", ".cache":
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !cppExts[strings.ToLower(filepath.Ext(path))] {
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
			if m := reCppInclude.FindStringSubmatch(line); m != nil {
				base := filepath.Base(strings.TrimSuffix(m[1], filepath.Ext(m[1])))
				lower := strings.ToLower(base)
				if pkgName, ok := pkgMap[lower]; ok {
					imported[pkgName] = true
				}
			}
		}
		return nil
	})

	return imported
}
