package interproc

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func TestJoinSummariesCapabilities(t *testing.T) {
	sym := ir.Symbol{Package: "p", Name: "f", Kind: "func"}
	node := ir.ContextNode{Function: sym, Context: ir.Context{}}

	a := ir.FunctionSummary{Node: node, Depth: 1, Confidence: 0.80}
	a.Effects.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})

	b := ir.FunctionSummary{Node: node, Depth: 2, Confidence: 0.90}
	b.Effects.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.90,
	})

	result := JoinSummaries(a, b)

	// Should have both capabilities
	if !result.Effects.Has(capability.CapExec) {
		t.Error("expected CapExec in merged effects")
	}
	if !result.Effects.Has(capability.CapNetwork) {
		t.Error("expected CapNetwork in merged effects")
	}

	// Depth = max(1, 2) = 2
	if result.Depth != 2 {
		t.Errorf("expected depth 2, got %d", result.Depth)
	}

	// Confidence = min(0.80, 0.90) = 0.80
	if result.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %.2f", result.Confidence)
	}
}

func TestJoinSummariesSources(t *testing.T) {
	sym := ir.Symbol{Package: "p", Name: "f", Kind: "func"}
	node := ir.ContextNode{Function: sym, Context: ir.Context{}}

	a := ir.FunctionSummary{Node: node, Confidence: 0.85}
	a.Sources.AddWithEvidence(capability.CapEnv, capability.CapabilityEvidence{
		Context: "test", Via: "import", Confidence: 0.85,
	})
	a.Sinks.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context: "test", Via: "callSite", Confidence: 0.75,
	})
	a.Sanitizers.AddWithEvidence(capability.CapCrypto, capability.CapabilityEvidence{
		Context: "test", Via: "import", Confidence: 0.90,
	})
	a.Transitive.AddWithEvidence(capability.CapFSRead, capability.CapabilityEvidence{
		Context: "test", Via: "import", Confidence: 0.80,
	})

	b := ir.FunctionSummary{Node: node, Confidence: 0.70}

	result := JoinSummaries(a, b)

	if !result.Sources.Has(capability.CapEnv) {
		t.Error("expected CapEnv in sources")
	}
	if !result.Sinks.Has(capability.CapExec) {
		t.Error("expected CapExec in sinks")
	}
	if !result.Sanitizers.Has(capability.CapCrypto) {
		t.Error("expected CapCrypto in sanitizers")
	}
	if !result.Transitive.Has(capability.CapFSRead) {
		t.Error("expected CapFSRead in transitive")
	}
	// Confidence = min(0.85, 0.70) = 0.70
	if result.Confidence != 0.70 {
		t.Errorf("expected confidence 0.70, got %.2f", result.Confidence)
	}
}

func TestJoinSummariesEqual(t *testing.T) {
	sym := ir.Symbol{Package: "p", Name: "f", Kind: "func"}
	node := ir.ContextNode{Function: sym, Context: ir.Context{}}

	a := ir.FunctionSummary{Node: node, Depth: 0, Confidence: 0.90}
	a.Effects.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context: "test", Via: "callSite", Confidence: 0.75,
	})

	b := a // Same content

	if !SummariesEqual(a, b) {
		t.Error("identical summaries should be equal")
	}
}

func TestJoinSummariesNotEqual(t *testing.T) {
	sym := ir.Symbol{Package: "p", Name: "f", Kind: "func"}
	node := ir.ContextNode{Function: sym, Context: ir.Context{}}

	a := ir.FunctionSummary{Node: node, Depth: 1}
	a.Effects.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context: "test", Via: "callSite", Confidence: 0.75,
	})

	b := ir.FunctionSummary{Node: node, Depth: 2}
	b.Effects.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Context: "test", Via: "import", Confidence: 0.90,
	})

	if SummariesEqual(a, b) {
		t.Error("different summaries should not be equal")
	}
}
