package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	swift "github.com/1homsi/gorisk/internal/adapters/swift"
)

// reSwiftImport matches top-level Swift import statements.
// Group 1 = framework/module name.
var reSwiftImport = regexp.MustCompile(`^import\s+([A-Za-z][A-Za-z0-9_]+)`)

// SwiftAnalyzer implements Analyzer using Swift import analysis.
type SwiftAnalyzer struct{}

func (SwiftAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeSwift(dir, "")
}

func (SwiftAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeSwift(dir, entryFile)
}

func analyzeSwift(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &swift.Adapter{}
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
		imported = collectSwiftFileImports(entryPath)
	} else {
		imported = collectSwiftProjectImports(dir)
	}

	// Build a lookup from lowercase package name to canonical package name
	// so we can match Swift framework imports (e.g. "Vapor") to SPM package
	// identities (e.g. "vapor").
	lowerToCanonical := make(map[string]string)
	for pkgName := range g.Packages {
		lowerToCanonical[strings.ToLower(pkgName)] = pkgName
	}

	// Normalise imported set to lowercase canonical names.
	normalised := make(map[string]bool)
	for name := range imported {
		lower := strings.ToLower(name)
		if canonical, ok := lowerToCanonical[lower]; ok {
			normalised[canonical] = true
		} else {
			normalised[lower] = true
		}
	}

	reachable := resolveReachable(normalised, g.Edges)

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

// collectSwiftFileImports scans a single .swift file for import statements.
func collectSwiftFileImports(path string) map[string]bool {
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
		if m := reSwiftImport.FindStringSubmatch(line); m != nil {
			imported[m[1]] = true
		}
	}
	return imported
}

// collectSwiftProjectImports scans all .swift files in dir, skipping .build
// and .swiftpm directories.
func collectSwiftProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		".build":   true,
		".swiftpm": true,
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
		if strings.ToLower(filepath.Ext(path)) != ".swift" {
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
			if m := reSwiftImport.FindStringSubmatch(line); m != nil {
				imported[m[1]] = true
			}
		}
		return nil
	})

	return imported
}
