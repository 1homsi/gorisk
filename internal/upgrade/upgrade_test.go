package upgrade

import (
	"encoding/json"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

func TestCapDiff(t *testing.T) {
	added := capability.CapabilitySet{}
	added.Add(capability.CapExec)

	removed := capability.CapabilitySet{}
	removed.Add(capability.CapCrypto)

	diff := CapDiff{
		Package:   "test/pkg",
		Added:     added,
		Removed:   removed,
		Escalated: true,
	}

	if diff.Package != "test/pkg" {
		t.Errorf("Package = %q, want %q", diff.Package, "test/pkg")
	}
	if !diff.Added.Has("exec") {
		t.Error("Expected Added to have 'exec'")
	}
	if !diff.Removed.Has("crypto") {
		t.Error("Expected Removed to have 'crypto'")
	}
	if !diff.Escalated {
		t.Error("Expected Escalated = true")
	}
}

func TestCapDiffNonEscalated(t *testing.T) {
	added := capability.CapabilitySet{}
	added.Add(capability.CapCrypto) // Low risk

	diff := CapDiff{
		Package:   "safe/pkg",
		Added:     added,
		Escalated: false,
	}

	if diff.Escalated {
		t.Error("Expected Escalated = false for low-risk capability")
	}
}

func TestUpgraderInterface(t *testing.T) {
	// Verify that both upgraders implement the Upgrader interface
	var _ Upgrader = GoUpgrader{}
	var _ Upgrader = NodeUpgrader{}

	t.Log("Both GoUpgrader and NodeUpgrader implement Upgrader interface")
}

func TestCapDifferInterface(t *testing.T) {
	// Verify that both differs implement the CapDiffer interface
	var _ CapDiffer = GoCapDiffer{}
	var _ CapDiffer = NodeCapDiffer{}

	t.Log("Both GoCapDiffer and NodeCapDiffer implement CapDiffer interface")
}

func TestCapDiffEmpty(t *testing.T) {
	diff := CapDiff{
		Package: "empty/pkg",
	}

	if diff.Added.Score != 0 {
		t.Errorf("Empty Added score = %d, want 0", diff.Added.Score)
	}
	if diff.Removed.Score != 0 {
		t.Errorf("Empty Removed score = %d, want 0", diff.Removed.Score)
	}
	if diff.Escalated {
		t.Error("Empty diff should not be escalated")
	}
}

func TestCapDiffMultipleCapabilities(t *testing.T) {
	added := capability.CapabilitySet{}
	added.Add(capability.CapExec)
	added.Add(capability.CapNetwork)
	added.Add(capability.CapUnsafe)

	diff := CapDiff{
		Package:   "multi/pkg",
		Added:     added,
		Escalated: true,
	}

	if !diff.Added.Has("exec") {
		t.Error("Expected exec capability")
	}
	if !diff.Added.Has("network") {
		t.Error("Expected network capability")
	}
	if !diff.Added.Has("unsafe") {
		t.Error("Expected unsafe capability")
	}

	// Should have high score due to multiple capabilities
	if diff.Added.Score < 30 {
		t.Errorf("Added score = %d, expected >= 30 for multiple risky capabilities", diff.Added.Score)
	}
}

func TestCapEscalated(t *testing.T) {
	tests := []struct {
		name     string
		old      capability.CapabilitySet
		new      capability.CapabilitySet
		expected bool
	}{
		{
			name:     "No change",
			old:      capability.CapabilitySet{},
			new:      capability.CapabilitySet{},
			expected: false,
		},
		{
			name: "High risk added",
			old:  capability.CapabilitySet{},
			new: func() capability.CapabilitySet {
				cs := capability.CapabilitySet{}
				cs.Add(capability.CapExec)
				return cs
			}(),
			expected: true,
		},
		{
			name: "Low risk added",
			old:  capability.CapabilitySet{},
			new: func() capability.CapabilitySet {
				cs := capability.CapabilitySet{}
				cs.Add(capability.CapCrypto)
				return cs
			}(),
			expected: false,
		},
		{
			name: "Score increases",
			old: func() capability.CapabilitySet {
				cs := capability.CapabilitySet{}
				cs.Add(capability.CapCrypto)
				return cs
			}(),
			new: func() capability.CapabilitySet {
				cs := capability.CapabilitySet{}
				cs.Add(capability.CapCrypto)
				cs.Add(capability.CapExec)
				return cs
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capEscalated(tt.old, tt.new)
			if got != tt.expected {
				t.Errorf("capEscalated() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ── nodeCurrentVersion ────────────────────────────────────────────────────────

func TestNodeCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "node_modules", "express")
	if err := os.MkdirAll(pkgDir, 0750); err != nil {
		t.Fatal(err)
	}
	meta := map[string]string{"version": "4.18.0"}
	b, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), b, 0600); err != nil {
		t.Fatal(err)
	}

	ver, err := nodeCurrentVersion(dir, "express")
	if err != nil {
		t.Fatalf("nodeCurrentVersion() error: %v", err)
	}
	if ver != "4.18.0" {
		t.Errorf("nodeCurrentVersion() = %q, want 4.18.0", ver)
	}
}

func TestNodeCurrentVersionMissing(t *testing.T) {
	_, err := nodeCurrentVersion(t.TempDir(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing package")
	}
}

// ── nodeModuleCaps ────────────────────────────────────────────────────────────

func TestNodeModuleCapsMissing(t *testing.T) {
	caps := nodeModuleCaps(t.TempDir(), "nonexistent")
	if caps.Score != 0 {
		t.Errorf("expected zero score for missing module, got %d", caps.Score)
	}
}

func TestNodeModuleCapsPresent(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "node_modules", "badpkg")
	if err := os.MkdirAll(pkgDir, 0750); err != nil {
		t.Fatal(err)
	}
	// File that triggers exec capability
	src := "const cp = require('child_process');\ncp.exec('ls');\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "index.js"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	caps := nodeModuleCaps(dir, "badpkg")
	if !caps.Has(capability.CapExec) {
		t.Error("expected exec capability from child_process import")
	}
}

// ── nodePackageDeps ───────────────────────────────────────────────────────────

func TestNodePackageDeps(t *testing.T) {
	dir := t.TempDir()
	content := `{"name":"test","dependencies":{"express":"^4.0","lodash":"^4.17"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	deps := nodePackageDeps(dir)
	if deps["express"] != "^4.0" {
		t.Errorf("express dep = %q, want ^4.0", deps["express"])
	}
	if deps["lodash"] != "^4.17" {
		t.Errorf("lodash dep = %q, want ^4.17", deps["lodash"])
	}
}

func TestNodePackageDepsNoFile(t *testing.T) {
	deps := nodePackageDeps(t.TempDir())
	if deps != nil {
		t.Errorf("expected nil for missing package.json, got %v", deps)
	}
}

func TestNodePackageDepsMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{bad json`), 0600); err != nil {
		t.Fatal(err)
	}
	deps := nodePackageDeps(dir)
	if deps != nil {
		t.Errorf("expected nil for malformed JSON, got %v", deps)
	}
}

// ── objectSig ─────────────────────────────────────────────────────────────────

func TestObjectSigVar(t *testing.T) {
	pkg := types.NewPackage("test/pkg", "pkg")
	v := types.NewVar(token.NoPos, pkg, "Count", types.Typ[types.Int])
	got := objectSig(v)
	if !strings.Contains(got, "var Count") {
		t.Errorf("objectSig(Var) = %q, want to contain 'var Count'", got)
	}
}

func TestObjectSigConst(t *testing.T) {
	pkg := types.NewPackage("test/pkg", "pkg")
	c := types.NewConst(token.NoPos, pkg, "MaxSize", types.Typ[types.Int], constant.MakeInt64(100))
	got := objectSig(c)
	if !strings.Contains(got, "const MaxSize") {
		t.Errorf("objectSig(Const) = %q, want to contain 'const MaxSize'", got)
	}
}

func TestObjectSigTypeName(t *testing.T) {
	pkg := types.NewPackage("test/pkg", "pkg")
	tn := types.NewTypeName(token.NoPos, pkg, "MyError", types.Universe.Lookup("error").Type())
	got := objectSig(tn)
	if !strings.Contains(got, "MyError") {
		t.Errorf("objectSig(TypeName) = %q, want to contain 'MyError'", got)
	}
}

func TestObjectSigFunc(t *testing.T) {
	pkg := types.NewPackage("test/pkg", "pkg")
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	fn := types.NewFunc(token.NoPos, pkg, "DoWork", sig)
	got := objectSig(fn)
	if got == "" {
		t.Error("objectSig(Func) should not be empty")
	}
}

// ── diffScopes ────────────────────────────────────────────────────────────────

func TestDiffScopesNilPackages(t *testing.T) {
	changes := diffScopes(nil, nil)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for nil packages, got %d", len(changes))
	}
}

func TestDiffScopesRemovedSymbol(t *testing.T) {
	oldPkg := types.NewPackage("test", "test")
	v := types.NewVar(token.NoPos, oldPkg, "Exported", types.Typ[types.Int])
	oldPkg.Scope().Insert(v)

	newPkg := types.NewPackage("test", "test")

	changes := diffScopes(oldPkg, newPkg)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Kind != "removed" {
		t.Errorf("Kind = %q, want removed", changes[0].Kind)
	}
	if changes[0].Symbol != "Exported" {
		t.Errorf("Symbol = %q, want Exported", changes[0].Symbol)
	}
}

func TestDiffScopesTypeChanged(t *testing.T) {
	oldPkg := types.NewPackage("test", "test")
	oldVar := types.NewVar(token.NoPos, oldPkg, "Value", types.Typ[types.Int])
	oldPkg.Scope().Insert(oldVar)

	newPkg := types.NewPackage("test", "test")
	newVar := types.NewVar(token.NoPos, newPkg, "Value", types.Typ[types.String])
	newPkg.Scope().Insert(newVar)

	changes := diffScopes(oldPkg, newPkg)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change for type mismatch, got %d", len(changes))
	}
	if changes[0].Kind != "type_changed" {
		t.Errorf("Kind = %q, want type_changed", changes[0].Kind)
	}
}

func TestDiffScopesNoChanges(t *testing.T) {
	oldPkg := types.NewPackage("test", "test")
	v := types.NewVar(token.NoPos, oldPkg, "Value", types.Typ[types.Int])
	oldPkg.Scope().Insert(v)

	newPkg := types.NewPackage("test", "test")
	v2 := types.NewVar(token.NoPos, newPkg, "Value", types.Typ[types.Int])
	newPkg.Scope().Insert(v2)

	changes := diffScopes(oldPkg, newPkg)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for identical scopes, got %d", len(changes))
	}
}

func TestDiffScopesUnexportedIgnored(t *testing.T) {
	oldPkg := types.NewPackage("test", "test")
	// lowercase = unexported
	v := types.NewVar(token.NoPos, oldPkg, "internal", types.Typ[types.Int])
	oldPkg.Scope().Insert(v)

	newPkg := types.NewPackage("test", "test")

	changes := diffScopes(oldPkg, newPkg)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes (unexported symbol), got %d", len(changes))
	}
}

func TestBuildDiffs(t *testing.T) {
	oldCaps := make(map[string]capability.CapabilitySet)
	oldExec := capability.CapabilitySet{}
	oldExec.Add(capability.CapExec)
	oldCaps["pkg1"] = oldExec

	newCaps := make(map[string]capability.CapabilitySet)
	newNetwork := capability.CapabilitySet{}
	newNetwork.Add(capability.CapNetwork)
	newCaps["pkg1"] = newNetwork
	newExec := capability.CapabilitySet{}
	newExec.Add(capability.CapExec)
	newCaps["pkg2"] = newExec

	diffs := buildDiffs(oldCaps, newCaps)

	// Should have diffs for pkg1 (changed) and pkg2 (new)
	if len(diffs) == 0 {
		t.Error("Expected non-empty diffs")
	}

	// Verify pkg1 has both added (network) and removed (exec)
	foundPkg1 := false
	for _, d := range diffs {
		if d.Package == "pkg1" {
			foundPkg1 = true
			if !d.Added.Has("network") {
				t.Error("Expected pkg1 to have added network capability")
			}
			if !d.Removed.Has("exec") {
				t.Error("Expected pkg1 to have removed exec capability")
			}
		}
	}
	if !foundPkg1 {
		t.Error("Expected to find pkg1 in diffs")
	}
}
