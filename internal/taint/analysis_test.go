package taint

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func buildCSCallGraph(funcPkg, funcName string, sources, sinks []capability.Capability) *ir.CSCallGraph {
	cg := ir.NewCSCallGraph()
	sym := ir.Symbol{Package: funcPkg, Name: funcName, Kind: "func"}
	ctx := ir.Context{}
	node := ir.ContextNode{Function: sym, Context: ctx}
	cg.Nodes[node.String()] = node

	summary := ir.FunctionSummary{Node: node, Confidence: 0.90}
	for _, s := range sources {
		summary.Sources.AddWithEvidence(s, capability.CapabilityEvidence{
			Context:    "test",
			Via:        "import",
			Confidence: 0.90,
		})
		summary.Effects.AddWithEvidence(s, capability.CapabilityEvidence{
			Context:    "test",
			Via:        "import",
			Confidence: 0.90,
		})
	}
	for _, s := range sinks {
		summary.Sinks.AddWithEvidence(s, capability.CapabilityEvidence{
			Context:    "test",
			Via:        "callSite",
			Confidence: 0.75,
		})
		summary.Effects.AddWithEvidence(s, capability.CapabilityEvidence{
			Context:    "test",
			Via:        "callSite",
			Confidence: 0.75,
		})
	}
	cg.Summaries[node.String()] = summary
	return cg
}

func TestSetVerbose(t *testing.T) {
	original := Verbose
	defer func() { Verbose = original }()

	SetVerbose(true)
	if !Verbose {
		t.Error("expected Verbose=true after SetVerbose(true)")
	}
	SetVerbose(false)
	if Verbose {
		t.Error("expected Verbose=false after SetVerbose(false)")
	}
}

func TestDebugAndInfoLogging(t *testing.T) {
	// Test that verbose logging doesn't panic
	original := Verbose
	defer func() { Verbose = original }()

	SetVerbose(true)
	debugf("test debug %s", "message")
	infof("test info %d", 42)
	SetVerbose(false)
	debugf("should not log")
	infof("should not log")
}

func TestNewInterprocedural(t *testing.T) {
	cg := ir.NewCSCallGraph()
	ta := NewInterprocedural(cg)
	if ta == nil {
		t.Fatal("NewInterprocedural returned nil")
	}
	if ta.CallGraph != cg {
		t.Error("CallGraph not set correctly")
	}
	if len(ta.Rules) == 0 {
		t.Error("Rules should be non-empty")
	}
}

func TestAnalyzeInterproceduralEmpty(t *testing.T) {
	cg := ir.NewCSCallGraph()
	ta := NewInterprocedural(cg)
	findings := ta.AnalyzeInterprocedural()
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty call graph, got %d", len(findings))
	}
}

func TestAnalyzeInterproceduralEnvExec(t *testing.T) {
	cg := buildCSCallGraph("test/pkg", "dangerous",
		[]capability.Capability{capability.CapEnv},
		[]capability.Capability{capability.CapExec},
	)
	ta := NewInterprocedural(cg)
	findings := ta.AnalyzeInterprocedural()

	found := false
	for _, f := range findings {
		if f.Source == capability.CapEnv && f.Sink == capability.CapExec {
			found = true
			if f.Risk != "HIGH" {
				t.Errorf("expected HIGH risk, got %s", f.Risk)
			}
			if f.Package == "" {
				t.Error("expected non-empty Package")
			}
		}
	}
	if !found {
		t.Error("expected env→exec finding")
	}
}

func TestAnalyzeInterproceduralVerbose(t *testing.T) {
	original := Verbose
	defer func() { Verbose = original }()
	SetVerbose(true)

	cg := buildCSCallGraph("test/pkg", "run",
		[]capability.Capability{capability.CapNetwork},
		[]capability.Capability{capability.CapExec},
	)
	ta := NewInterprocedural(cg)
	findings := ta.AnalyzeInterprocedural()

	if len(findings) == 0 {
		t.Error("expected at least one finding")
	}
}

func TestAnalyzeInterproceduralTransitiveSources(t *testing.T) {
	// Build a graph where the source is in transitive (not direct sources)
	cg := ir.NewCSCallGraph()
	sym := ir.Symbol{Package: "test/pkg", Name: "fn", Kind: "func"}
	ctx := ir.Context{}
	node := ir.ContextNode{Function: sym, Context: ctx}
	cg.Nodes[node.String()] = node

	summary := ir.FunctionSummary{Node: node, Confidence: 0.85}
	summary.Transitive.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.85,
	})
	summary.Sinks.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.80,
	})
	cg.Summaries[node.String()] = summary

	ta := NewInterprocedural(cg)
	findings := ta.AnalyzeInterprocedural()

	found := false
	for _, f := range findings {
		if f.Source == capability.CapNetwork && f.Sink == capability.CapExec {
			found = true
		}
	}
	if !found {
		t.Error("expected network→exec finding via transitive sources")
	}
}

func TestAnalyzeInterproceduralCalleeSource(t *testing.T) {
	// Caller has exec sink; callee has env source
	cg := ir.NewCSCallGraph()

	callerSym := ir.Symbol{Package: "test", Name: "caller", Kind: "func"}
	calleeSym := ir.Symbol{Package: "test", Name: "callee", Kind: "func"}
	callerCtx := ir.Context{}
	calleeCtx := ir.Context{Caller: callerSym}

	callerNode := ir.ContextNode{Function: callerSym, Context: callerCtx}
	calleeNode := ir.ContextNode{Function: calleeSym, Context: calleeCtx}

	cg.Nodes[callerNode.String()] = callerNode
	cg.Nodes[calleeNode.String()] = calleeNode
	cg.Edges[callerNode.String()] = []ir.ContextNode{calleeNode}

	callerSummary := ir.FunctionSummary{Node: callerNode, Confidence: 0.90}
	callerSummary.Sinks.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})
	callerSummary.Transitive.AddWithEvidence(capability.CapEnv, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.90,
	})

	calleeSummary := ir.FunctionSummary{Node: calleeNode, Confidence: 0.90}
	calleeSummary.Sources.AddWithEvidence(capability.CapEnv, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.90,
	})

	cg.Summaries[callerNode.String()] = callerSummary
	cg.Summaries[calleeNode.String()] = calleeSummary

	ta := NewInterprocedural(cg)
	findings := ta.AnalyzeInterprocedural()
	_ = findings // Just verify it doesn't panic
}

func TestAnalyzeInterproceduralCalleeSink(t *testing.T) {
	// Caller has env source; callee has exec sink
	cg := ir.NewCSCallGraph()

	callerSym := ir.Symbol{Package: "test", Name: "caller", Kind: "func"}
	calleeSym := ir.Symbol{Package: "test", Name: "callee", Kind: "func"}
	callerCtx := ir.Context{}
	calleeCtx := ir.Context{Caller: callerSym}

	callerNode := ir.ContextNode{Function: callerSym, Context: callerCtx}
	calleeNode := ir.ContextNode{Function: calleeSym, Context: calleeCtx}

	cg.Nodes[callerNode.String()] = callerNode
	cg.Nodes[calleeNode.String()] = calleeNode
	cg.Edges[callerNode.String()] = []ir.ContextNode{calleeNode}

	callerSummary := ir.FunctionSummary{Node: callerNode, Confidence: 0.90}
	callerSummary.Sources.AddWithEvidence(capability.CapEnv, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.90,
	})
	callerSummary.Transitive.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})

	calleeSummary := ir.FunctionSummary{Node: calleeNode, Confidence: 0.90}
	calleeSummary.Sinks.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})

	cg.Summaries[callerNode.String()] = callerSummary
	cg.Summaries[calleeNode.String()] = calleeSummary

	ta := NewInterprocedural(cg)
	findings := ta.AnalyzeInterprocedural()
	_ = findings // Just verify it doesn't panic
}

func TestFormatCallStack(t *testing.T) {
	ta := &TaintAnalysis{CallGraph: ir.NewCSCallGraph(), Rules: taintRules}

	// Empty path
	result := ta.formatCallStack(nil)
	if result != nil {
		t.Errorf("expected nil for empty path, got %v", result)
	}

	// Non-empty path
	caller := ir.Symbol{Package: "mypkg", Name: "outer", Kind: "func"}
	callee := ir.Symbol{Package: "mypkg", Name: "inner", Kind: "func"}
	path := []ir.CallEdge{
		{Caller: caller, Callee: callee},
	}
	stack := ta.formatCallStack(path)
	if len(stack) != 2 {
		t.Fatalf("expected stack of length 2, got %d: %v", len(stack), stack)
	}
	if stack[0] != "mypkg.outer" {
		t.Errorf("stack[0] = %q, want mypkg.outer", stack[0])
	}
	if stack[1] != "mypkg.inner" {
		t.Errorf("stack[1] = %q, want mypkg.inner", stack[1])
	}
}

func TestDeduplicateFindings(t *testing.T) {
	findings := []TaintFinding{
		{Package: "foo", Source: capability.CapEnv, Sink: capability.CapExec, Risk: "HIGH"},
		{Package: "foo", Source: capability.CapEnv, Sink: capability.CapExec, Risk: "HIGH"}, // duplicate
		{Package: "bar", Source: capability.CapNetwork, Sink: capability.CapExec, Risk: "HIGH"},
	}
	deduped := deduplicateFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 findings after dedup, got %d", len(deduped))
	}
}

func TestDeduplicateFindingsEmpty(t *testing.T) {
	result := deduplicateFindings(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %v", result)
	}
}

// TestTraceTaintFlowBFS verifies that traceTaintFlow correctly finds multi-hop paths.
// The setup mirrors what AnalyzeInterprocedural sees after the fixpoint:
//
//	srcNode: has network (Sources) + exec (Transitive, propagated from snkNode)
//	midNode: empty
//	snkNode: has exec (Sinks+Effects)
//
// traceTaintFlow is called on srcNode and must BFS forward to find snkNode.
func TestTraceTaintFlowBFS(t *testing.T) {
	cg := ir.NewCSCallGraph()

	srcSym := ir.Symbol{Package: "test", Name: "src", Kind: "func"}
	midSym := ir.Symbol{Package: "test", Name: "mid", Kind: "func"}
	snkSym := ir.Symbol{Package: "test", Name: "snk", Kind: "func"}

	srcNode := ir.ContextNode{Function: srcSym, Context: ir.Context{}}
	midNode := ir.ContextNode{Function: midSym, Context: ir.Context{Caller: srcSym}}
	snkNode := ir.ContextNode{Function: snkSym, Context: ir.Context{Caller: midSym}}

	cg.Nodes[srcNode.String()] = srcNode
	cg.Nodes[midNode.String()] = midNode
	cg.Nodes[snkNode.String()] = snkNode
	cg.Edges[srcNode.String()] = []ir.ContextNode{midNode}
	cg.Edges[midNode.String()] = []ir.ContextNode{snkNode}

	// srcNode: network in Sources; exec in Transitive (as if fixpoint propagated it)
	srcSummary := ir.FunctionSummary{Node: srcNode, Confidence: 0.90}
	srcSummary.Sources.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Via: "import", Confidence: 0.90,
	})
	srcSummary.Effects.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Via: "import", Confidence: 0.90,
	})
	srcSummary.Transitive.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Via: "propagated", Confidence: 0.55,
	})

	midSummary := ir.FunctionSummary{Node: midNode, Confidence: 0.90}

	snkSummary := ir.FunctionSummary{Node: snkNode, Confidence: 0.90}
	snkSummary.Sinks.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Via: "callSite", Confidence: 0.75,
	})
	snkSummary.Effects.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Via: "callSite", Confidence: 0.75,
	})

	cg.Summaries[srcNode.String()] = srcSummary
	cg.Summaries[midNode.String()] = midSummary
	cg.Summaries[snkNode.String()] = snkSummary

	ta := NewInterprocedural(cg)
	flow := ta.traceTaintFlow(srcNode, capability.CapNetwork, capability.CapExec)

	if flow == nil {
		t.Fatal("expected non-nil flow for multi-hop path")
	}
	// The BFS should walk from srcNode → midNode → snkNode and find exec there.
	if len(flow.CallPath) == 0 {
		t.Error("expected non-empty call path for multi-hop flow")
	}
	if flow.SinkFunction.Name != "snk" {
		t.Errorf("SinkFunction.Name = %q, want snk", flow.SinkFunction.Name)
	}
}

// TestTraceTaintFlowDirectSameFn verifies flows within a single function.
func TestTraceTaintFlowDirectSameFn(t *testing.T) {
	cg := buildCSCallGraph("test/pkg", "doAll",
		[]capability.Capability{capability.CapEnv},
		[]capability.Capability{capability.CapExec},
	)
	ta := NewInterprocedural(cg)

	node := cg.Nodes[func() string {
		for k := range cg.Nodes {
			return k
		}
		return ""
	}()]

	flow := ta.traceTaintFlow(node, capability.CapEnv, capability.CapExec)
	if flow == nil {
		t.Fatal("expected non-nil flow")
	}
	// Same function has both — path should be empty
	if len(flow.CallPath) != 0 {
		t.Errorf("expected empty call path for same-function flow, got %d", len(flow.CallPath))
	}
}

func TestGetConfidence(t *testing.T) {
	ta := &TaintAnalysis{CallGraph: ir.NewCSCallGraph(), Rules: taintRules}

	summary := ir.FunctionSummary{Confidence: 0.50}
	summary.Effects.AddWithEvidence(capability.CapEnv, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.90,
	})
	summary.Sources.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.80,
	})
	summary.Sinks.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})
	summary.Transitive.AddWithEvidence(capability.CapFSRead, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.70,
	})

	// From Effects
	if conf := ta.getConfidence(summary, capability.CapEnv); conf != 0.90 {
		t.Errorf("Effects confidence = %.2f, want 0.90", conf)
	}
	// From Sources
	if conf := ta.getConfidence(summary, capability.CapNetwork); conf != 0.80 {
		t.Errorf("Sources confidence = %.2f, want 0.80", conf)
	}
	// From Sinks
	if conf := ta.getConfidence(summary, capability.CapExec); conf != 0.75 {
		t.Errorf("Sinks confidence = %.2f, want 0.75", conf)
	}
	// From Transitive
	if conf := ta.getConfidence(summary, capability.CapFSRead); conf != 0.70 {
		t.Errorf("Transitive confidence = %.2f, want 0.70", conf)
	}
	// Default fallback
	if conf := ta.getConfidence(summary, capability.CapUnsafe); conf != 0.50 {
		t.Errorf("Default confidence = %.2f, want 0.50", conf)
	}
}
