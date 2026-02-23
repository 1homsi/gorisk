package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	kotlinadapter "github.com/1homsi/gorisk/internal/adapters/kotlin"
)

// reKotlinImport matches Kotlin/Java import statements.
var reKotlinImport = regexp.MustCompile(`^import\s+([\w.]+)`)

// KotlinAnalyzer implements Analyzer using Kotlin import-statement analysis.
type KotlinAnalyzer struct{}

func (KotlinAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeKotlin(dir, "")
}

func (KotlinAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeKotlin(dir, entryFile)
}

// analyzeKotlin scans the project's Kotlin source files to determine which
// installed Gradle packages are actually used ("reachable").
func analyzeKotlin(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &kotlinadapter.Adapter{}
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
		imported = collectKotlinFileImports(entryPath)
	} else {
		imported = collectKotlinProjectImports(dir)
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

// collectKotlinFileImports scans a single .kt/.kts file for import statements.
func collectKotlinFileImports(path string) map[string]bool {
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
		if m := reKotlinImport.FindStringSubmatch(line); m != nil {
			pkg := mavenCoordsFromJavaPackage(m[1])
			if pkg != "" {
				imported[pkg] = true
			}
		}
	}
	return imported
}

// collectKotlinProjectImports scans all .kt and .kts files in a directory
// (excluding build/ and .gradle/).
func collectKotlinProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "build" || name == ".gradle" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".kt" && ext != ".kts" {
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
			if m := reKotlinImport.FindStringSubmatch(line); m != nil {
				pkg := mavenCoordsFromJavaPackage(m[1])
				if pkg != "" {
					imported[pkg] = true
				}
			}
		}
		return nil
	})

	return imported
}

// mavenCoordsFromJavaPackage converts a Java-style package name to Maven
// group:artifact coordinates using the first two segments as group and
// the third as artifact.
// e.g. "com.google.guava.collect" → "com.google:guava"
func mavenCoordsFromJavaPackage(pkg string) string {
	parts := strings.Split(pkg, ".")
	if len(parts) < 3 {
		return ""
	}
	group := parts[0] + "." + parts[1]
	artifact := parts[2]
	return group + ":" + artifact
}
