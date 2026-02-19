package interproc

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func TestFixpointLinearChain(t *testing.T) {
	// Create a linear chain: A → B → C
	// C has exec capability, should propagate to B and A
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}
	nodeB := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "B"}}
	nodeC := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "C"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Nodes[nodeB.String()] = nodeB
	cg.Nodes[nodeC.String()] = nodeC

	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeB}
	cg.Edges[nodeB.String()] = []ir.ContextNode{nodeC}

	cg.ReverseEdges[nodeB.String()] = []ir.ContextNode{nodeA}
	cg.ReverseEdges[nodeC.String()] = []ir.ContextNode{nodeB}

	// C has exec capability
	summaryC := ir.FunctionSummary{
		Node:       nodeC,
		Confidence: 1.0,
	}
	summaryC.Effects.Add(capability.CapExec)
	ClassifySummary(&summaryC)
	cg.Summaries[nodeC.String()] = summaryC

	// Initialize A and B with empty summaries
	cg.Summaries[nodeA.String()] = ir.FunctionSummary{Node: nodeA, Confidence: 1.0}
	cg.Summaries[nodeB.String()] = ir.FunctionSummary{Node: nodeB, Confidence: 1.0}

	// Run fixpoint
	err := ComputeFixpoint(cg, 100)
	if err != nil {
		t.Fatalf("Fixpoint failed: %v", err)
	}

	// Check that exec propagated to B and A
	summaryB := cg.Summaries[nodeB.String()]
	if !summaryB.Transitive.Has(capability.CapExec) {
		t.Error("Expected B to have transitive exec capability")
	}

	summaryA := cg.Summaries[nodeA.String()]
	if !summaryA.Transitive.Has(capability.CapExec) {
		t.Error("Expected A to have transitive exec capability")
	}

	// Check depth values
	if summaryC.Depth != 0 {
		t.Errorf("Expected C depth 0, got %d", summaryC.Depth)
	}
	if summaryB.Depth != 1 {
		t.Errorf("Expected B depth 1, got %d", summaryB.Depth)
	}
	if summaryA.Depth != 2 {
		t.Errorf("Expected A depth 2, got %d", summaryA.Depth)
	}

	// Check confidence decay
	if summaryB.Confidence >= 1.0 {
		t.Errorf("Expected B confidence < 1.0, got %f", summaryB.Confidence)
	}
	if summaryA.Confidence >= summaryB.Confidence {
		t.Errorf("Expected A confidence < B confidence, got A=%f B=%f", summaryA.Confidence, summaryB.Confidence)
	}
}

func TestFixpointCycle(t *testing.T) {
	// Create a cycle: A → B → A
	// A has network capability, should detect SCC and handle it
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}
	nodeB := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "B"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Nodes[nodeB.String()] = nodeB

	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeB}
	cg.Edges[nodeB.String()] = []ir.ContextNode{nodeA}

	cg.ReverseEdges[nodeA.String()] = []ir.ContextNode{nodeB}
	cg.ReverseEdges[nodeB.String()] = []ir.ContextNode{nodeA}

	// A has network capability
	summaryA := ir.FunctionSummary{
		Node:       nodeA,
		Confidence: 1.0,
	}
	summaryA.Effects.Add(capability.CapNetwork)
	ClassifySummary(&summaryA)
	cg.Summaries[nodeA.String()] = summaryA

	// Initialize B
	cg.Summaries[nodeB.String()] = ir.FunctionSummary{Node: nodeB, Confidence: 1.0}

	// Detect SCCs first
	DetectSCCs(cg)

	// Should have one SCC
	if len(cg.SCCs) != 1 {
		t.Fatalf("Expected 1 SCC, got %d", len(cg.SCCs))
	}

	// Run fixpoint
	err := ComputeFixpoint(cg, 100)
	if err != nil {
		t.Fatalf("Fixpoint failed: %v", err)
	}

	// Both should have the capability (collapsed SCC)
	summaryAFinal := cg.Summaries[nodeA.String()]
	summaryBFinal := cg.Summaries[nodeB.String()]

	if !summaryAFinal.Sources.Has(capability.CapNetwork) {
		t.Error("Expected A to have network capability")
	}
	if !summaryBFinal.Sources.Has(capability.CapNetwork) {
		t.Error("Expected B to have network capability (from SCC collapse)")
	}
}

func TestFixpointConvergence(t *testing.T) {
	// Create a diamond: A → B, A → C, B → D, C → D
	// D has exec, should propagate through both paths
	cg := ir.NewCSCallGraph()

	nodeA := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "A"}}
	nodeB := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "B"}}
	nodeC := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "C"}}
	nodeD := ir.ContextNode{Function: ir.Symbol{Package: "pkg", Name: "D"}}

	cg.Nodes[nodeA.String()] = nodeA
	cg.Nodes[nodeB.String()] = nodeB
	cg.Nodes[nodeC.String()] = nodeC
	cg.Nodes[nodeD.String()] = nodeD

	cg.Edges[nodeA.String()] = []ir.ContextNode{nodeB, nodeC}
	cg.Edges[nodeB.String()] = []ir.ContextNode{nodeD}
	cg.Edges[nodeC.String()] = []ir.ContextNode{nodeD}

	cg.ReverseEdges[nodeB.String()] = []ir.ContextNode{nodeA}
	cg.ReverseEdges[nodeC.String()] = []ir.ContextNode{nodeA}
	cg.ReverseEdges[nodeD.String()] = []ir.ContextNode{nodeB, nodeC}

	// D has exec
	summaryD := ir.FunctionSummary{
		Node:       nodeD,
		Confidence: 1.0,
	}
	summaryD.Effects.Add(capability.CapExec)
	ClassifySummary(&summaryD)
	cg.Summaries[nodeD.String()] = summaryD

	// Initialize others
	cg.Summaries[nodeA.String()] = ir.FunctionSummary{Node: nodeA, Confidence: 1.0}
	cg.Summaries[nodeB.String()] = ir.FunctionSummary{Node: nodeB, Confidence: 1.0}
	cg.Summaries[nodeC.String()] = ir.FunctionSummary{Node: nodeC, Confidence: 1.0}

	// Run fixpoint
	err := ComputeFixpoint(cg, 100)
	if err != nil {
		t.Fatalf("Fixpoint failed: %v", err)
	}

	// All should have exec in transitive
	for _, node := range []ir.ContextNode{nodeA, nodeB, nodeC} {
		summary := cg.Summaries[node.String()]
		if !summary.Transitive.Has(capability.CapExec) {
			t.Errorf("Expected %s to have transitive exec capability", node.Function.Name)
		}
	}
}
