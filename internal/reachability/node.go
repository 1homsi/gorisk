package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	node "github.com/1homsi/gorisk/internal/adapters/node"
)

var (
	reRequire    = regexp.MustCompile(`require\(['"]([^'"./][^'"]*)['"]\)`)
	reImportFrom = regexp.MustCompile(`from\s+['"]([^'"./][^'"]*)['"]`)
	reImportDyn  = regexp.MustCompile(`import\(['"]([^'"./][^'"]*)['"]`)
)

// analyzeNode scans the project's own source files to determine which
// installed npm packages are actually imported ("reachable"), and returns
// their capability sets from the dependency graph.
func analyzeNode(dir string) ([]ReachabilityReport, error) {
	adapter := &node.Adapter{}
	g, err := adapter.Load(dir)
	if err != nil {
		return nil, err
	}

	// Collect all imports made by the project's own source files.
	imported := collectProjectImports(dir)

	// Walk all packages in the graph; a package is "reachable" if the project
	// directly imports it (or transitively via another reachable package).
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

// collectProjectImports scans the project's own JS/TS source files (excluding
// node_modules) and returns the set of bare module specifiers that are imported.
func collectProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".ts" && ext != ".tsx" && ext != ".mjs" && ext != ".cjs" {
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
			for _, re := range []*regexp.Regexp{reRequire, reImportFrom, reImportDyn} {
				for _, m := range re.FindAllStringSubmatch(line, -1) {
					if len(m) > 1 {
						// Normalise scoped packages: "@scope/pkg/sub" → "@scope/pkg"
						pkg := bareModuleName(m[1])
						imported[pkg] = true
					}
				}
			}
		}
		return nil
	})

	return imported
}

// resolveReachable does a BFS over the edges map starting from directly
// imported packages to find all transitively reachable packages.
func resolveReachable(seed map[string]bool, edges map[string][]string) map[string]bool {
	reachable := make(map[string]bool)
	queue := make([]string, 0, len(seed))
	for pkg := range seed {
		queue = append(queue, pkg)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if reachable[cur] {
			continue
		}
		reachable[cur] = true
		for _, dep := range edges[cur] {
			if !reachable[dep] {
				queue = append(queue, dep)
			}
		}
	}
	return reachable
}

// bareModuleName strips subpath exports to get the root package name.
// e.g. "lodash/fp" → "lodash", "@scope/pkg/utils" → "@scope/pkg"
func bareModuleName(spec string) string {
	if strings.HasPrefix(spec, "@") {
		// scoped: keep first two segments
		parts := strings.SplitN(spec, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return spec
	}
	// unscoped: keep first segment
	if idx := strings.Index(spec, "/"); idx != -1 {
		return spec[:idx]
	}
	return spec
}
