package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	javaadapter "github.com/1homsi/gorisk/internal/adapters/java"
)

// reImportJava matches Java import statements and captures the fully-qualified
// class name: `import com.example.Foo;` or `import static com.example.Foo.*;`
var reImportJava = regexp.MustCompile(`^\s*import\s+(?:static\s+)?([\w.]+)`)

// JavaAnalyzer implements Analyzer using Java import analysis.
type JavaAnalyzer struct{}

func (JavaAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeJava(dir, "")
}

func (JavaAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeJava(dir, entryFile)
}

// analyzeJava scans the project's .java files to determine which installed
// packages are actually used ("reachable").
func analyzeJava(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &javaadapter.Adapter{}
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
		imported = collectJavaFileImports(entryPath)
	} else {
		imported = collectJavaProjectImports(dir)
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

// collectJavaFileImports scans a single .java file for import statements and
// maps them to the vendor-prefix form used in package names ("groupId/artifactId").
func collectJavaFileImports(path string) map[string]bool {
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
		if m := reImportJava.FindStringSubmatch(line); m != nil {
			if pkg := javaPackageFromImport(m[1]); pkg != "" {
				imported[pkg] = true
			}
		}
	}
	return imported
}

// collectJavaProjectImports scans all .java source files in a directory,
// excluding common build-output directories.
func collectJavaProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	skipDirs := map[string]bool{
		"target": true, "build": true, ".gradle": true, ".git": true,
		"out": true, ".idea": true,
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
		if strings.ToLower(filepath.Ext(path)) != ".java" {
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
			if m := reImportJava.FindStringSubmatch(line); m != nil {
				if pkg := javaPackageFromImport(m[1]); pkg != "" {
					imported[pkg] = true
				}
			}
		}
		return nil
	})

	return imported
}

// javaPackageFromImport converts a Java fully-qualified import to the
// groupId/artifactId key used in the dependency graph.
// e.g. "com.fasterxml.jackson.databind.ObjectMapper" → "com.fasterxml/jackson-databind"
// Best-effort: use the first two namespace segments as groupId, third as artifactId.
func javaPackageFromImport(fqn string) string {
	parts := strings.Split(fqn, ".")
	if len(parts) < 2 {
		return ""
	}
	if len(parts) == 2 {
		return parts[0] + "/" + parts[1]
	}
	// groupId = first two parts joined with ".", artifactId = third part.
	return parts[0] + "." + parts[1] + "/" + parts[2]
}
