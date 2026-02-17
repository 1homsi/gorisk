package impact

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/report"
)

func Compute(g *graph.DependencyGraph, modulePath string) report.ImpactReport {
	r := report.ImpactReport{
		Module: modulePath,
	}

	mod, ok := g.Modules[modulePath]
	if !ok {
		return r
	}
	if mod.Version != "" {
		r.Version = mod.Version
	}

	removed := make(map[string]struct{})
	for _, pkg := range mod.Packages {
		removed[pkg.ImportPath] = struct{}{}
	}

	rev := g.ReverseEdges()

	affected := make(map[string]int)
	queue := make([]string, 0, len(removed))
	for p := range removed {
		queue = append(queue, p)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, parent := range rev[cur] {
			if _, alreadyRemoved := removed[parent]; alreadyRemoved {
				continue
			}
			if depth, seen := affected[parent]; !seen || affected[cur]+1 > depth {
				newDepth := affected[cur] + 1
				affected[parent] = newDepth
				if newDepth > r.Depth {
					r.Depth = newDepth
				}
				queue = append(queue, parent)
			}
		}
	}

	for pkgPath := range affected {
		r.AffectedPackages = append(r.AffectedPackages, pkgPath)

		if pkg, ok := g.Packages[pkgPath]; ok {
			r.LOCTouched += countLOC(pkg.Dir, pkg.GoFiles)

			if isMain(pkg) {
				r.AffectedMains = append(r.AffectedMains, pkgPath)
			}
		}
	}

	return r
}

func isMain(pkg *graph.Package) bool {
	return pkg != nil && pkg.Name == "main"
}

func countLOC(dir string, files []string) int {
	total := 0
	for _, f := range files {
		path := filepath.Join(dir, f)
		n, err := countFileLOC(path)
		if err == nil {
			total += n
		}
	}
	return total
}

func countFileLOC(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			count++
		}
	}
	return count, scanner.Err()
}
