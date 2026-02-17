package viz

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/transitive"
)

//go:embed template.html
var htmlTemplate string

type nodeData struct {
	ID           string   `json:"id"`
	Risk         string   `json:"risk"`
	Score        int      `json:"score"`
	Depth        int      `json:"depth"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type edgeData struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type graphData struct {
	Nodes []nodeData `json:"nodes"`
	Edges []edgeData `json:"edges"`
}

func Run(args []string) int {
	fs := flag.NewFlagSet("viz", flag.ExitOnError)
	minRisk := fs.String("min-risk", "low", "minimum risk level to show: low|medium|high")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	g, err := graph.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	risks := transitive.ComputeTransitiveRisk(g)

	capsByModule := make(map[string][]string)
	for _, pkg := range g.Packages {
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}
		for _, c := range pkg.Capabilities.List() {
			if !hasString(capsByModule[pkg.Module.Path], c) {
				capsByModule[pkg.Module.Path] = append(capsByModule[pkg.Module.Path], c)
			}
		}
	}

	minLevel := riskValue(*minRisk)
	included := make(map[string]bool)
	var nodes []nodeData
	for _, r := range risks {
		if riskValue(r.RiskLevel) < minLevel {
			continue
		}
		included[r.Module] = true
		nodes = append(nodes, nodeData{
			ID:           r.Module,
			Risk:         r.RiskLevel,
			Score:        r.EffectiveScore,
			Depth:        r.Depth,
			Capabilities: capsByModule[r.Module],
		})
	}

	modDeps := buildModuleDeps(g)
	edgeSeen := make(map[string]bool)
	var edges []edgeData
	for src, targets := range modDeps {
		if !included[src] {
			continue
		}
		for _, tgt := range targets {
			if !included[tgt] {
				continue
			}
			key := src + "→" + tgt
			if !edgeSeen[key] {
				edgeSeen[key] = true
				edges = append(edges, edgeData{Source: src, Target: tgt})
			}
		}
	}

	if nodes == nil {
		nodes = []nodeData{}
	}
	if edges == nil {
		edges = []edgeData{}
	}

	dataJSON, err := json.Marshal(graphData{Nodes: nodes, Edges: edges})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		return 2
	}

	fmt.Print(strings.Replace(htmlTemplate, "__DATA__", string(dataJSON), 1))
	return 0
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
			if toMod != fromMod && !seen[fromMod][toMod] {
				seen[fromMod][toMod] = true
				modDeps[fromMod] = append(modDeps[fromMod], toMod)
			}
		}
	}
	return modDeps
}

func riskValue(level string) int {
	switch strings.ToLower(level) {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func hasString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
