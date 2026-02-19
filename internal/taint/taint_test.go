package taint

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

func makePackage(importPath, modPath string, caps ...capability.Capability) *graph.Package {
	mod := &graph.Module{Path: modPath}
	pkg := &graph.Package{
		ImportPath: importPath,
		Module:     mod,
	}
	for _, c := range caps {
		pkg.Capabilities.Add(c)
	}
	return pkg
}

func TestAnalyzeEnvExec(t *testing.T) {
	pkgs := map[string]*graph.Package{
		"foo/shell": makePackage("foo/shell", "foo", capability.CapEnv, capability.CapExec),
	}
	findings := Analyze(pkgs)
	if len(findings) == 0 {
		t.Fatal("expected at least one taint finding")
	}
	found := false
	for _, f := range findings {
		if f.Source == capability.CapEnv && f.Sink == capability.CapExec && f.Risk == "HIGH" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected env→exec HIGH finding, got: %+v", findings)
	}
}

func TestAnalyzeNetworkExec(t *testing.T) {
	pkgs := map[string]*graph.Package{
		"foo/runner": makePackage("foo/runner", "foo", capability.CapNetwork, capability.CapExec),
	}
	findings := Analyze(pkgs)
	found := false
	for _, f := range findings {
		if f.Source == capability.CapNetwork && f.Sink == capability.CapExec && f.Risk == "HIGH" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected network→exec HIGH finding, got: %+v", findings)
	}
}

func TestAnalyzeNoFindings(t *testing.T) {
	pkgs := map[string]*graph.Package{
		"foo/safe": makePackage("foo/safe", "foo", capability.CapFSRead),
	}
	findings := Analyze(pkgs)
	// fs:read alone should not trigger any HIGH findings
	for _, f := range findings {
		if f.Risk == "HIGH" {
			t.Errorf("unexpected HIGH finding for fs:read-only package: %+v", f)
		}
	}
}

func TestAnalyzeSortedHighFirst(t *testing.T) {
	pkgs := map[string]*graph.Package{
		"a/low":  makePackage("a/low", "a", capability.CapEnv, capability.CapFSWrite),     // LOW
		"b/high": makePackage("b/high", "b", capability.CapNetwork, capability.CapExec),   // HIGH
		"c/med":  makePackage("c/med", "c", capability.CapNetwork, capability.CapFSWrite), // MEDIUM
	}
	findings := Analyze(pkgs)
	if len(findings) == 0 {
		t.Fatal("expected taint findings")
	}
	// First finding should be HIGH
	if findings[0].Risk != "HIGH" {
		t.Errorf("expected HIGH first, got %q: %+v", findings[0].Risk, findings)
	}
}

func TestAnalyzeMultiplePairs(t *testing.T) {
	// Package has env, network, exec → should trigger env→exec AND network→exec
	pkgs := map[string]*graph.Package{
		"foo/multi": makePackage("foo/multi", "foo", capability.CapEnv, capability.CapNetwork, capability.CapExec),
	}
	findings := Analyze(pkgs)

	hasPair := func(src, sink string) bool {
		for _, f := range findings {
			if f.Source == src && f.Sink == sink {
				return true
			}
		}
		return false
	}

	if !hasPair(capability.CapEnv, capability.CapExec) {
		t.Error("expected env→exec pair")
	}
	if !hasPair(capability.CapNetwork, capability.CapExec) {
		t.Error("expected network→exec pair")
	}
}

func TestAnalyzeFields(t *testing.T) {
	pkgs := map[string]*graph.Package{
		"foo/pkg": makePackage("foo/pkg", "foo/mod", capability.CapFSRead, capability.CapNetwork),
	}
	findings := Analyze(pkgs)
	for _, f := range findings {
		if f.Package == "" {
			t.Error("expected non-empty Package")
		}
		if f.Module == "" {
			t.Error("expected non-empty Module")
		}
		if f.Risk == "" {
			t.Error("expected non-empty Risk")
		}
		if f.Note == "" {
			t.Error("expected non-empty Note")
		}
	}
}

func TestAnalyzeEmptyPackages(t *testing.T) {
	findings := Analyze(map[string]*graph.Package{})
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty packages, got: %+v", findings)
	}
}

func TestAnalyzeConfidence(t *testing.T) {
	// Create a package with capabilities that have evidence with known confidence
	pkg := &graph.Package{
		ImportPath: "test/pkg",
		Module:     &graph.Module{Path: "test"},
	}
	// Add env capability with confidence 0.90
	pkg.Capabilities.AddWithEvidence(capability.CapEnv, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "import",
		Confidence: 0.90,
	})
	// Add exec capability with confidence 0.75
	pkg.Capabilities.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})

	pkgs := map[string]*graph.Package{"test/pkg": pkg}
	findings := Analyze(pkgs)

	// Should find env→exec taint
	var envExecFinding *TaintFinding
	for i := range findings {
		if findings[i].Source == capability.CapEnv && findings[i].Sink == capability.CapExec {
			envExecFinding = &findings[i]
			break
		}
	}

	if envExecFinding == nil {
		t.Fatal("expected env→exec finding")
	}

	// Confidence should be min(0.90, 0.75) = 0.75
	if envExecFinding.Confidence != 0.75 {
		t.Errorf("expected confidence 0.75, got %.2f", envExecFinding.Confidence)
	}

	// Evidence chain should have two entries
	if len(envExecFinding.EvidenceChain) != 2 {
		t.Errorf("expected evidence chain length 2, got %d", len(envExecFinding.EvidenceChain))
	}
}

func TestAnalyzeConfidenceDowngrade(t *testing.T) {
	// Create a package with low confidence capabilities
	pkg := &graph.Package{
		ImportPath: "test/pkg",
		Module:     &graph.Module{Path: "test"},
	}
	// Add network with confidence 0.60 (< 0.70)
	pkg.Capabilities.AddWithEvidence(capability.CapNetwork, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.60,
	})
	// Add exec with confidence 0.80
	pkg.Capabilities.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.80,
	})

	pkgs := map[string]*graph.Package{"test/pkg": pkg}
	findings := Analyze(pkgs)

	// Should find network→exec taint
	var netExecFinding *TaintFinding
	for i := range findings {
		if findings[i].Source == capability.CapNetwork && findings[i].Sink == capability.CapExec {
			netExecFinding = &findings[i]
			break
		}
	}

	if netExecFinding == nil {
		t.Fatal("expected network→exec finding")
	}

	// Confidence is min(0.60, 0.80) = 0.60, which is < 0.70
	// So risk should be downgraded from HIGH to MEDIUM
	if netExecFinding.Risk != "MEDIUM" {
		t.Errorf("expected downgraded risk MEDIUM, got %s", netExecFinding.Risk)
	}
}

func TestAnalyzeNewRules(t *testing.T) {
	tests := []struct {
		name   string
		source capability.Capability
		sink   capability.Capability
		risk   string
	}{
		{"network→plugin", capability.CapNetwork, capability.CapPlugin, "HIGH"},
		{"fs:read→plugin", capability.CapFSRead, capability.CapPlugin, "HIGH"},
		{"env→crypto", capability.CapEnv, capability.CapCrypto, "MEDIUM"},
		{"network→reflect", capability.CapNetwork, capability.CapReflect, "MEDIUM"},
		{"fs:read→unsafe", capability.CapFSRead, capability.CapUnsafe, "HIGH"},
		{"env→network", capability.CapEnv, capability.CapNetwork, "MEDIUM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := makePackage("test/pkg", "test", tt.source, tt.sink)
			pkgs := map[string]*graph.Package{"test/pkg": pkg}
			findings := Analyze(pkgs)

			found := false
			for _, f := range findings {
				if f.Source == tt.source && f.Sink == tt.sink && f.Risk == tt.risk {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s→%s %s finding, got: %+v", tt.source, tt.sink, tt.risk, findings)
			}
		})
	}
}
