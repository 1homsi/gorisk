package goadapter

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func TestPropagateAcrossPackages(t *testing.T) {
	// Set up two packages: pkgA and pkgB
	// pkgA has mainFunc that calls pkgB.Helper
	// pkgB.Helper has direct exec capability
	// We expect mainFunc to gain transitive exec capability

	pkgACaps := map[string]ir.FunctionCaps{
		"pkgA.mainFunc": {
			Symbol: ir.Symbol{Package: "pkgA", Name: "mainFunc", Kind: "func"},
		},
	}

	pkgBCaps := map[string]ir.FunctionCaps{
		"pkgB.Helper": {
			Symbol:     ir.Symbol{Package: "pkgB", Name: "Helper", Kind: "func"},
			DirectCaps: makeCapSet(capability.CapExec, 0.90),
		},
	}

	edges := []ir.CallEdge{
		{
			Caller: ir.Symbol{Package: "pkgA", Name: "mainFunc", Kind: "func"},
			Callee: ir.Symbol{Package: "pkgB", Name: "Helper", Kind: "func"},
		},
	}

	pkgCaps := map[string]map[string]ir.FunctionCaps{
		"pkgA": pkgACaps,
		"pkgB": pkgBCaps,
	}
	pkgEdges := map[string][]ir.CallEdge{
		"pkgA": edges,
	}

	result := PropagateAcrossPackages(pkgCaps, pkgEdges)

	mainFunc := result["pkgA"]["pkgA.mainFunc"]
	if !mainFunc.TransitiveCaps.Has(capability.CapExec) {
		t.Errorf("expected mainFunc to have transitive exec capability")
	}

	// Check confidence multiplier (hop 1 = 0.70)
	conf := mainFunc.TransitiveCaps.Confidence(capability.CapExec)
	expected := 0.90 * 0.70
	if conf < expected-0.01 || conf > expected+0.01 {
		t.Errorf("expected confidence ~%.2f, got %.2f", expected, conf)
	}
}

func makeCapSet(cap capability.Capability, confidence float64) capability.CapabilitySet {
	var cs capability.CapabilitySet
	cs.AddWithEvidence(cap, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "test",
		Confidence: confidence,
	})
	return cs
}
