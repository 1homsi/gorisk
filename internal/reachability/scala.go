package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	scalaadapter "github.com/1homsi/gorisk/internal/adapters/scala"
)

// reScalaImport matches Scala import statements.
var reScalaImport = regexp.MustCompile(`^import\s+([\w.]+)`)

// ScalaAnalyzer implements Analyzer using Scala import-statement analysis.
type ScalaAnalyzer struct{}

func (ScalaAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeScala(dir, "")
}

func (ScalaAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeScala(dir, entryFile)
}

// analyzeScala scans the project's Scala source files to determine which
// installed sbt packages are actually used ("reachable").
func analyzeScala(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &scalaadapter.Adapter{}
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
		imported = collectScalaFileImports(entryPath)
	} else {
		imported = collectScalaProjectImports(dir)
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

// collectScalaFileImports scans a single .scala file for import statements.
func collectScalaFileImports(path string) map[string]bool {
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
		if m := reScalaImport.FindStringSubmatch(line); m != nil {
			pkg := mavenCoordsFromJavaPackage(m[1])
			if pkg != "" {
				imported[pkg] = true
			}
		}
	}
	return imported
}

// collectScalaProjectImports scans all .scala files in a directory
// (excluding target/ and project/target/).
func collectScalaProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// Skip target/ but allow project/ (just not project/target/).
			if name == "target" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".scala" {
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
			if m := reScalaImport.FindStringSubmatch(line); m != nil {
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
