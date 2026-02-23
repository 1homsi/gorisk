package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	haskelladapter "github.com/1homsi/gorisk/internal/adapters/haskell"
)

// reHaskellImport matches Haskell import statements (qualified or plain).
var reHaskellImport = regexp.MustCompile(`^import\s+(?:qualified\s+)?([A-Z][A-Za-z0-9.]+)`)

// HaskellAnalyzer implements Analyzer using Haskell import-statement analysis.
type HaskellAnalyzer struct{}

func (HaskellAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeHaskell(dir, "")
}

func (HaskellAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeHaskell(dir, entryFile)
}

// analyzeHaskell scans the project's Haskell source files to determine which
// installed Cabal/Stack packages are actually used ("reachable").
func analyzeHaskell(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &haskelladapter.Adapter{}
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
		imported = collectHaskellFileImports(entryPath)
	} else {
		imported = collectHaskellProjectImports(dir)
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

// haskellModuleToPackage extracts the top-level module name (first segment
// before '.') and converts it to lowercase for matching against package names.
// e.g. "Data.Aeson" → "aeson" (first segment is "Data", but Hackage packages
// use the library name, so we use the first segment after standard prefixes).
// Best-effort: use the first segment as lowercase.
func haskellModuleToPackage(module string) string {
	if module == "" {
		return ""
	}
	// Take the first segment (top-level namespace).
	dot := strings.IndexByte(module, '.')
	var top string
	if dot >= 0 {
		top = module[:dot]
	} else {
		top = module
	}
	return strings.ToLower(top)
}

// collectHaskellFileImports scans a single .hs/.lhs file for import statements.
func collectHaskellFileImports(path string) map[string]bool {
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
		if m := reHaskellImport.FindStringSubmatch(line); m != nil {
			pkg := haskellModuleToPackage(m[1])
			if pkg != "" {
				imported[pkg] = true
			}
		}
	}
	return imported
}

// collectHaskellProjectImports scans all .hs and .lhs files in a directory
// (excluding dist/, dist-newstyle/, .stack-work/).
func collectHaskellProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			switch name {
			case "dist", "dist-newstyle", ".stack-work":
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".hs" && ext != ".lhs" {
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
			if m := reHaskellImport.FindStringSubmatch(line); m != nil {
				pkg := haskellModuleToPackage(m[1])
				if pkg != "" {
					imported[pkg] = true
				}
			}
		}
		return nil
	})

	return imported
}
