package interproc

import (
	"testing"

	"github.com/1homsi/gorisk/internal/ir"
)

func TestTarjanSimpleCycle(t *testing.T) {
	// Create a simple cycle: A → B → C → A
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}
	nodeB := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "B"}}
	nodeC := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "C"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Nodes[nodeB.String()] = nodeB
	cg.Nodes[nodeC.String()] = nodeC

	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeB}
	cg.Edges[nodeB.String()] = []ir.ContextNode{nodeC}
	cg.Edges[nodeC.String()] = []ir.ContextNode{nodeA}

	// Run SCC detection
	DetectSCCs(cg)

	// All three nodes should be in the same SCC
	if len(cg.SCCs) != 1 {
		t.Errorf("Expected 1 SCC, got %d", len(cg.SCCs))
	}

	// Check that all nodes map to the same SCC
	sccID := cg.NodeToSCC[nodeA.String()]
	if cg.NodeToSCC[nodeB.String()] != sccID {
		t.Error("Node B should be in the same SCC as A")
	}
	if cg.NodeToSCC[nodeC.String()] != sccID {
		t.Error("Node C should be in the same SCC as A")
	}

	// Check that the SCC contains all three nodes
	scc := cg.SCCs[sccID]
	if len(scc.Nodes) != 3 {
		t.Errorf("Expected SCC to contain 3 nodes, got %d", len(scc.Nodes))
	}
}

func TestTarjanMultipleSCCs(t *testing.T) {
	// Create two cycles: A → B → A and C → D → C, with E → C
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}
	nodeB := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "B"}}
	nodeC := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "C"}}
	nodeD := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "D"}}
	nodeE := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "E"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Nodes[nodeB.String()] = nodeB
	cg.Nodes[nodeC.String()] = nodeC
	cg.Nodes[nodeD.String()] = nodeD
	cg.Nodes[nodeE.String()] = nodeE

	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeB}
	cg.Edges[nodeB.String()] = []ir.ContextNode{nodeA}
	cg.Edges[nodeC.String()] = []ir.ContextNode{nodeD}
	cg.Edges[nodeD.String()] = []ir.ContextNode{nodeC}
	cg.Edges[nodeE.String()] = []ir.ContextNode{nodeC}

	// Run SCC detection
	DetectSCCs(cg)

	// Should have 2 SCCs (A-B and C-D)
	if len(cg.SCCs) != 2 {
		t.Errorf("Expected 2 SCCs, got %d", len(cg.SCCs))
	}

	// A and B should be in one SCC
	sccA := cg.NodeToSCC[nodeA.String()]
	sccB := cg.NodeToSCC[nodeB.String()]
	if sccA != sccB {
		t.Error("Nodes A and B should be in the same SCC")
	}

	// C and D should be in another SCC
	sccC := cg.NodeToSCC[nodeC.String()]
	sccD := cg.NodeToSCC[nodeD.String()]
	if sccC != sccD {
		t.Error("Nodes C and D should be in the same SCC")
	}

	// A-B SCC and C-D SCC should be different
	if sccA == sccC {
		t.Error("A-B and C-D should be in different SCCs")
	}

	// E should not be in an SCC (no self-loop or cycle)
	if _, inSCC := cg.NodeToSCC[nodeE.String()]; inSCC {
		t.Error("Node E should not be in an SCC")
	}
}

func TestTarjanSelfLoop(t *testing.T) {
	// Create a self-loop: A → A
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeA}

	// Run SCC detection
	DetectSCCs(cg)

	// Should have 1 SCC containing just A
	if len(cg.SCCs) != 1 {
		t.Errorf("Expected 1 SCC, got %d", len(cg.SCCs))
	}

	sccID := cg.NodeToSCC[nodeA.String()]
	scc := cg.SCCs[sccID]
	if len(scc.Nodes) != 1 {
		t.Errorf("Expected SCC to contain 1 node, got %d", len(scc.Nodes))
	}
}

func TestTarjanNoCycles(t *testing.T) {
	// Create a DAG: A → B → C
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}
	nodeB := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "B"}}
	nodeC := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "C"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Nodes[nodeB.String()] = nodeB
	cg.Nodes[nodeC.String()] = nodeC

	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeB}
	cg.Edges[nodeB.String()] = []ir.ContextNode{nodeC}

	// Run SCC detection
	DetectSCCs(cg)

	// Should have no SCCs (no cycles)
	if len(cg.SCCs) != 0 {
		t.Errorf("Expected 0 SCCs, got %d", len(cg.SCCs))
	}
}
