package interproc

import (
	"testing"

	"github.com/1homsi/gorisk/internal/ir"
)

func buildSimpleGraph() *ir.CSCallGraph {
	cg := ir.NewCSCallGraph()

	root := ir.ContextNode{Function: ir.Symbol{Package: "p", Name: "root", Kind: "func"}, Context: ir.Context{}}
	mid := ir.ContextNode{Function: ir.Symbol{Package: "p", Name: "mid", Kind: "func"}, Context: ir.Context{}}
	leaf := ir.ContextNode{Function: ir.Symbol{Package: "p", Name: "leaf", Kind: "func"}, Context: ir.Context{}}

	cg.Nodes[root.String()] = root
	cg.Nodes[mid.String()] = mid
	cg.Nodes[leaf.String()] = leaf

	cg.Edges[root.String()] = []ir.ContextNode{mid}
	cg.Edges[mid.String()] = []ir.ContextNode{leaf}
	cg.Edges[leaf.String()] = nil

	cg.ReverseEdges[mid.String()] = []ir.ContextNode{root}
	cg.ReverseEdges[leaf.String()] = []ir.ContextNode{mid}

	return cg
}

func TestReverseTopologicalSort(t *testing.T) {
	cg := buildSimpleGraph()
	order := ReverseTopologicalSort(cg)

	if len(order) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(order))
	}
	// In reverse topo order (roots first), root should come before leaf
	rootIdx, leafIdx := -1, -1
	for i, n := range order {
		if n.Function.Name == "root" {
			rootIdx = i
		}
		if n.Function.Name == "leaf" {
			leafIdx = i
		}
	}
	if rootIdx == -1 || leafIdx == -1 {
		t.Fatal("root or leaf not found in order")
	}
	if rootIdx >= leafIdx {
		t.Errorf("expected root before leaf in reverse topo order, got root=%d leaf=%d", rootIdx, leafIdx)
	}
}

func TestReverseTopologicalSortEmpty(t *testing.T) {
	cg := ir.NewCSCallGraph()
	order := ReverseTopologicalSort(cg)
	if len(order) != 0 {
		t.Errorf("expected empty result for empty graph, got %d nodes", len(order))
	}
}

func TestGetRoots(t *testing.T) {
	cg := buildSimpleGraph()
	roots := GetRoots(cg)

	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d: %v", len(roots), roots)
	}
	if roots[0].Function.Name != "root" {
		t.Errorf("expected root node, got %q", roots[0].Function.Name)
	}
}

func TestGetRootsEmpty(t *testing.T) {
	cg := ir.NewCSCallGraph()
	roots := GetRoots(cg)
	if len(roots) != 0 {
		t.Errorf("expected no roots for empty graph, got %v", roots)
	}
}

func TestGetLeaves(t *testing.T) {
	cg := buildSimpleGraph()
	leaves := GetLeaves(cg)

	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d: %v", len(leaves), leaves)
	}
	if leaves[0].Function.Name != "leaf" {
		t.Errorf("expected leaf node, got %q", leaves[0].Function.Name)
	}
}

func TestGetLeavesEmpty(t *testing.T) {
	cg := ir.NewCSCallGraph()
	leaves := GetLeaves(cg)
	if len(leaves) != 0 {
		t.Errorf("expected no leaves for empty graph, got %v", leaves)
	}
}
