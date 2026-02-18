package transitive

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

func buildGraph(mods map[string]int, edges map[string][]string) *graph.DependencyGraph {
	g := graph.NewDependencyGraph()

	main := &graph.Module{Path: "main", Main: true}
	g.Main = main
	g.Modules["main"] = main
	mainPkg := &graph.Package{ImportPath: "main", Module: main}
	g.Packages["main"] = mainPkg

	for modPath, score := range mods {
		mod := &graph.Module{Path: modPath, Version: "v1.0.0"}
		g.Modules[modPath] = mod
		var cs capability.CapabilitySet
		if score > 0 {
			// Add enough caps to reach the target score
			for cs.Score < score {
				cs.Add(capability.CapNetwork) // adds 15 per call (capped by dedup)
				break
			}
		}
		pkg := &graph.Package{ImportPath: modPath, Module: mod, Capabilities: cs}
		g.Packages[modPath] = pkg
		mod.Packages = []*graph.Package{pkg}
	}

	for from, tos := range edges {
		g.Edges[from] = tos
	}
	return g
}

func TestComputeTransitiveRiskDeterministic(t *testing.T) {
	g := buildGraph(
		map[string]int{
			"example.com/a": 15,
			"example.com/b": 20,
			"example.com/c": 5,
		},
		map[string][]string{
			"main":          {"example.com/a", "example.com/b"},
			"example.com/a": {"example.com/c"},
		},
	)

	results1 := ComputeTransitiveRisk(g)
	results2 := ComputeTransitiveRisk(g)

	if len(results1) != len(results2) {
		t.Fatalf("inconsistent result counts: %d vs %d", len(results1), len(results2))
	}
	for i := range results1 {
		if results1[i].Module != results2[i].Module {
			t.Errorf("index %d: got %q then %q — non-deterministic order", i, results1[i].Module, results2[i].Module)
		}
	}
}

func TestComputeTransitiveRiskSorted(t *testing.T) {
	g := buildGraph(
		map[string]int{
			"example.com/z": 15,
			"example.com/a": 15,
			"example.com/m": 15,
		},
		nil,
	)

	results := ComputeTransitiveRisk(g)
	for i := 1; i < len(results); i++ {
		if results[i-1].Module > results[i].Module {
			t.Errorf("results not sorted: %q > %q at index %d", results[i-1].Module, results[i].Module, i)
		}
	}
}

func TestComputeTransitiveRiskExcludesMain(t *testing.T) {
	g := buildGraph(map[string]int{"example.com/a": 15}, nil)

	results := ComputeTransitiveRisk(g)
	for _, r := range results {
		if r.Module == "main" {
			t.Errorf("main module should not appear in results")
		}
	}
}

func TestRiskLevel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "LOW"},
		{9, "LOW"},
		{10, "MEDIUM"},
		{29, "MEDIUM"},
		{30, "HIGH"},
		{100, "HIGH"},
	}
	for _, tt := range tests {
		if got := riskLevel(tt.score); got != tt.want {
			t.Errorf("riskLevel(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
