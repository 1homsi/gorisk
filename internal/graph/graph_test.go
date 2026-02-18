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

func buildTestGraph() *DependencyGraph {
	g := NewDependencyGraph()
	main := &Module{Path: "example.com/main", Main: true}
	g.Main = main
	g.Modules["example.com/main"] = main

	modA := &Module{Path: "example.com/a", Version: "v1.0.0"}
	modB := &Module{Path: "example.com/b", Version: "v2.0.0"}
	g.Modules["example.com/a"] = modA
	g.Modules["example.com/b"] = modB

	pkgA := &Package{ImportPath: "example.com/a", Module: modA}
	pkgB := &Package{ImportPath: "example.com/b", Module: modB}
	g.Packages["example.com/a"] = pkgA
	g.Packages["example.com/b"] = pkgB
	modA.Packages = []*Package{pkgA}
	modB.Packages = []*Package{pkgB}

	g.Edges["example.com/a"] = []string{"example.com/b"}
	return g
}

func TestChecksumDeterministic(t *testing.T) {
	g := buildTestGraph()
	c1 := g.Checksum()
	c2 := g.Checksum()
	if c1 != c2 {
		t.Errorf("Checksum is not deterministic: %s != %s", c1, c2)
	}
	if len(c1) != 16 {
		t.Errorf("expected 16-char hex checksum, got %q (len=%d)", c1, len(c1))
	}
}

func TestChecksumChangesWithNewModule(t *testing.T) {
	g1 := buildTestGraph()
	g2 := buildTestGraph()

	c1 := g1.Checksum()

	// Add a new module to g2
	modC := &Module{Path: "example.com/c", Version: "v1.0.0"}
	g2.Modules["example.com/c"] = modC
	pkgC := &Package{ImportPath: "example.com/c", Module: modC}
	g2.Packages["example.com/c"] = pkgC
	modC.Packages = []*Package{pkgC}

	c2 := g2.Checksum()
	if c1 == c2 {
		t.Error("Checksum should differ when a new module is added")
	}
}

func TestChecksumIgnoresMainModule(t *testing.T) {
	// Two graphs with different main module names but same deps should have same checksum
	g1 := buildTestGraph()
	g2 := buildTestGraph()
	g2.Main.Path = "example.com/other-main"
	g2.Modules["example.com/other-main"] = g2.Main
	delete(g2.Modules, "example.com/main")

	if g1.Checksum() != g2.Checksum() {
		t.Error("Checksum should not change when only the main module name changes")
	}
}

func TestChecksumEmptyGraph(t *testing.T) {
	g := NewDependencyGraph()
	c := g.Checksum()
	if len(c) != 16 {
		t.Errorf("expected 16-char checksum for empty graph, got %q", c)
	}
}
