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
