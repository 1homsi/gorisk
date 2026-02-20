package upgrade

import (
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
