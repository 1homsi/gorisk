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
