package ir

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

func TestSymbolString(t *testing.T) {
	tests := []struct {
		sym  Symbol
		want string
	}{
		{Symbol{Package: "os/exec", Name: "Command", Kind: "func"}, "os/exec.Command"},
		{Symbol{Package: "", Name: "helper", Kind: "func"}, ".helper"},
		{Symbol{Package: "net/http", Name: "Client.Do", Kind: "method"}, "net/http.Client.Do"},
	}
	for _, tt := range tests {
		if got := tt.sym.String(); got != tt.want {
			t.Errorf("Symbol.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestFunctionCapsDirectCaps(t *testing.T) {
	sym := Symbol{Package: "mypkg", Name: "Run", Kind: "func"}
	fc := FunctionCaps{Symbol: sym}
	fc.DirectCaps.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		File:       "run.go",
		Line:       10,
		Context:    "exec.Command",
		Via:        "callSite",
		Confidence: 0.75,
	})
	if fc.Symbol.Name != "Run" {
		t.Errorf("Symbol.Name = %q, want Run", fc.Symbol.Name)
	}

	if !fc.DirectCaps.Has(capability.CapExec) {
		t.Error("expected CapExec in DirectCaps")
	}
	if fc.DirectCaps.Score == 0 {
		t.Error("expected non-zero score")
	}
}

func TestIRGraphFunctions(t *testing.T) {
	g := IRGraph{
		Functions: make(map[string]FunctionCaps),
	}
	sym := Symbol{Package: "", Name: "foo", Kind: "func"}
	g.Functions[sym.String()] = FunctionCaps{Symbol: sym}

	if _, ok := g.Functions[".foo"]; !ok {
		t.Error("expected .foo in Functions map")
	}
}

func TestCallEdge(t *testing.T) {
	caller := Symbol{Package: "", Name: "bar", Kind: "func"}
	callee := Symbol{Package: "os/exec", Name: "Command", Kind: "func"}
	edge := CallEdge{Caller: caller, Callee: callee}
	edge.File = "bar.go"
	edge.Line = 5

	if edge.File != "bar.go" || edge.Line != 5 {
		t.Errorf("edge location = %s:%d, want bar.go:5", edge.File, edge.Line)
	}
	if edge.Caller.String() != ".bar" {
		t.Errorf("Caller.String() = %q", edge.Caller.String())
	}
	if edge.Callee.String() != "os/exec.Command" {
		t.Errorf("Callee.String() = %q", edge.Callee.String())
	}
}
