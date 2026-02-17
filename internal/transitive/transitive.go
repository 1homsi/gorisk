package transitive

import "github.com/1homsi/gorisk/internal/graph"

type ModuleRisk struct {
	Module          string
	DirectScore     int
	TransitiveScore int
	EffectiveScore  int
	Depth           int
	RiskLevel       string
}

func riskLevel(score int) string {
	switch {
	case score >= 30:
		return "HIGH"
	case score >= 10:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func ComputeTransitiveRisk(g *graph.DependencyGraph) []ModuleRisk {
	pkgDepth := computeDepths(g)

	moduleMaxCap := make(map[string]int)
	moduleDepth := make(map[string]int)

	for _, pkg := range g.Packages {
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}
		mp := pkg.Module.Path
		if pkg.Capabilities.Score > moduleMaxCap[mp] {
			moduleMaxCap[mp] = pkg.Capabilities.Score
		}
		d := pkgDepth[pkg.ImportPath]
		if d > moduleDepth[mp] {
			moduleDepth[mp] = d
		}
	}

	modDeps := buildModuleDeps(g)

	var results []ModuleRisk
	for _, mod := range g.Modules {
		if mod.Main {
			continue
		}
		direct := moduleMaxCap[mod.Path]
		transitive := computeTransitiveScore(mod.Path, moduleMaxCap, modDeps, make(map[string]bool))
		effective := direct + transitive/2
		if effective > 100 {
			effective = 100
		}
		results = append(results, ModuleRisk{
			Module:          mod.Path,
			DirectScore:     direct,
			TransitiveScore: transitive,
			EffectiveScore:  effective,
			Depth:           moduleDepth[mod.Path],
			RiskLevel:       riskLevel(effective),
		})
	}
	return results
}

func computeDepths(g *graph.DependencyGraph) map[string]int {
	depths := make(map[string]int)
	if g.Main == nil {
		return depths
	}
	visited := make(map[string]bool)
	queue := []struct {
		pkg   string
		depth int
	}{}
	for _, pkg := range g.Main.Packages {
		queue = append(queue, struct {
			pkg   string
			depth int
		}{pkg.ImportPath, 0})
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur.pkg] {
			continue
		}
		visited[cur.pkg] = true
		depths[cur.pkg] = cur.depth
		for _, imp := range g.Edges[cur.pkg] {
			if !visited[imp] {
				queue = append(queue, struct {
					pkg   string
					depth int
				}{imp, cur.depth + 1})
			}
		}
	}
	return depths
}

func buildModuleDeps(g *graph.DependencyGraph) map[string][]string {
	modDeps := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for pkgPath, imports := range g.Edges {
		pkg := g.Packages[pkgPath]
		if pkg == nil || pkg.Module == nil {
			continue
		}
		fromMod := pkg.Module.Path
		if seen[fromMod] == nil {
			seen[fromMod] = make(map[string]bool)
		}
		for _, imp := range imports {
			impPkg := g.Packages[imp]
			if impPkg == nil || impPkg.Module == nil {
				continue
			}
			toMod := impPkg.Module.Path
			if toMod == fromMod {
				continue
			}
			if !seen[fromMod][toMod] {
				seen[fromMod][toMod] = true
				modDeps[fromMod] = append(modDeps[fromMod], toMod)
			}
		}
	}
	return modDeps
}

func computeTransitiveScore(modPath string, scores map[string]int, deps map[string][]string, visited map[string]bool) int {
	if visited[modPath] {
		return 0
	}
	visited[modPath] = true
	total := 0
	for i, dep := range deps[modPath] {
		depth := i + 1
		s := scores[dep] + computeTransitiveScore(dep, scores, deps, visited)
		if depth > 0 {
			s = s / (depth + 1)
		}
		total += s
	}
	return total
}
