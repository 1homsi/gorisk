package graph

import "testing"

func TestNewDependencyGraph(t *testing.T) {
	g := NewDependencyGraph()
	if g.Modules == nil || g.Packages == nil || g.Edges == nil {
		t.Fatal("NewDependencyGraph should initialize all maps")
	}
}

func TestReverseEdges(t *testing.T) {
	g := NewDependencyGraph()
	g.Edges["a"] = []string{"b", "c"}
	g.Edges["d"] = []string{"b"}

	rev := g.ReverseEdges()

	if len(rev["b"]) != 2 {
		t.Fatalf("b should have 2 reverse edges, got %d", len(rev["b"]))
	}
	if len(rev["c"]) != 1 || rev["c"][0] != "a" {
		t.Fatalf("c should have 1 reverse edge from a, got %v", rev["c"])
	}
	if len(rev["a"]) != 0 {
		t.Fatalf("a has no reverse edges, got %v", rev["a"])
	}
}

func TestReverseEdgesEmpty(t *testing.T) {
	g := NewDependencyGraph()
	rev := g.ReverseEdges()
	if len(rev) != 0 {
		t.Fatalf("expected empty reverse edges, got %v", rev)
	}
}
