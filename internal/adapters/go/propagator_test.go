package goadapter

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func makeFC(name string, caps ...capability.Capability) ir.FunctionCaps {
	sym := ir.Symbol{Package: "", Name: name, Kind: "func"}
	fc := ir.FunctionCaps{Symbol: sym}
	for _, c := range caps {
		fc.DirectCaps.AddWithEvidence(c, capability.CapabilityEvidence{
			File:       "test.go",
			Line:       1,
			Context:    "test",
			Via:        "callSite",
			Confidence: 0.75,
		})
	}
	return fc
}

func TestPropagateWithinPackageBasic(t *testing.T) {
	// helper() has exec, main() calls helper() → main should get exec transitively.
	funcs := map[string]ir.FunctionCaps{
		".helper": makeFC("helper", capability.CapExec),
		".main":   makeFC("main"),
	}
	calls := []ir.CallEdge{
		{Caller: ir.Symbol{Name: "main"}, Callee: ir.Symbol{Name: "helper"}},
	}

	result := PropagateWithinPackage(funcs, calls)

	mainFC := result[".main"]
	if !mainFC.TransitiveCaps.Has(capability.CapExec) {
		t.Errorf("expected CapExec in main.TransitiveCaps after propagation, got: %v", mainFC.TransitiveCaps.List())
	}

	// Confidence should be decayed: 0.75 * 0.70 = 0.525
	evs := mainFC.TransitiveCaps.Evidence[capability.CapExec]
	if len(evs) == 0 {
		t.Fatal("expected evidence for CapExec in main.TransitiveCaps")
	}
	for _, ev := range evs {
		if ev.Via != "transitive" {
			t.Errorf("expected Via=transitive, got %q", ev.Via)
		}
		const want = 0.75 * 0.70
		if ev.Confidence < want-0.001 || ev.Confidence > want+0.001 {
			t.Errorf("expected confidence ~%.3f, got %.3f", want, ev.Confidence)
		}
	}
}

func TestPropagateWithinPackageNoUnknownCallee(t *testing.T) {
	// Edge to an unknown callee should not panic.
	funcs := map[string]ir.FunctionCaps{
		".main": makeFC("main"),
	}
	calls := []ir.CallEdge{
		{Caller: ir.Symbol{Name: "main"}, Callee: ir.Symbol{Name: "unknownFunc"}},
	}

	result := PropagateWithinPackage(funcs, calls)
	mainFC := result[".main"]
	if mainFC.TransitiveCaps.Has(capability.CapExec) {
		t.Error("unexpected CapExec in main from unknown callee")
	}
}

func TestPropagateWithinPackageChain(t *testing.T) {
	// a() → b() → c() where c has network; a should get transitive network at 2 hops.
	funcs := map[string]ir.FunctionCaps{
		".a": makeFC("a"),
		".b": makeFC("b"),
		".c": makeFC("c", capability.CapNetwork),
	}
	calls := []ir.CallEdge{
		{Caller: ir.Symbol{Name: "a"}, Callee: ir.Symbol{Name: "b"}},
		{Caller: ir.Symbol{Name: "b"}, Callee: ir.Symbol{Name: "c"}},
	}

	result := PropagateWithinPackage(funcs, calls)

	// b should have network transitively (hop 1 from c)
	bFC := result[".b"]
	if !bFC.TransitiveCaps.Has(capability.CapNetwork) {
		t.Errorf("expected CapNetwork in b.TransitiveCaps, got: %v", bFC.TransitiveCaps.List())
	}

	// a should have network transitively (hop 2 from c through b)
	aFC := result[".a"]
	if !aFC.TransitiveCaps.Has(capability.CapNetwork) {
		t.Errorf("expected CapNetwork in a.TransitiveCaps, got: %v", aFC.TransitiveCaps.List())
	}
}

func TestPropagateWithinPackageDirectCapsUntouched(t *testing.T) {
	// Propagation should not modify DirectCaps.
	funcs := map[string]ir.FunctionCaps{
		".caller": makeFC("caller"),
		".callee": makeFC("callee", capability.CapExec),
	}
	calls := []ir.CallEdge{
		{Caller: ir.Symbol{Name: "caller"}, Callee: ir.Symbol{Name: "callee"}},
	}

	result := PropagateWithinPackage(funcs, calls)

	callerFC := result[".caller"]
	if callerFC.DirectCaps.Has(capability.CapExec) {
		t.Error("propagation should not add to DirectCaps, only TransitiveCaps")
	}
}

func TestHopMultiplier(t *testing.T) {
	tests := []struct {
		hops int
		want float64
	}{
		{0, 1.00},
		{1, 0.70},
		{2, 0.55},
		{3, 0.40},
		{5, 0.40},
	}
	for _, tt := range tests {
		got := hopMultiplier(tt.hops)
		if got != tt.want {
			t.Errorf("hopMultiplier(%d) = %v, want %v", tt.hops, got, tt.want)
		}
	}
}
