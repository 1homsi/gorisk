package capability

import (
	"testing"
)

func TestCapabilitySetAdd(t *testing.T) {
	var cs CapabilitySet
	cs.Add(CapFSRead)
	if !cs.Has(CapFSRead) {
		t.Fatal("expected CapFSRead to be set")
	}
	if cs.Score != capWeights[CapFSRead] {
		t.Fatalf("expected score %d, got %d", capWeights[CapFSRead], cs.Score)
	}

	cs.Add(CapFSRead)
	if cs.Score != capWeights[CapFSRead] {
		t.Fatal("Add should be idempotent: score should not increase on duplicate")
	}
}

func TestCapabilitySetMerge(t *testing.T) {
	var a, b CapabilitySet
	a.Add(CapFSRead)
	b.Add(CapNetwork)
	a.Merge(b)

	if !a.Has(CapFSRead) || !a.Has(CapNetwork) {
		t.Fatal("merged set should contain both capabilities")
	}
	want := capWeights[CapFSRead] + capWeights[CapNetwork]
	if a.Score != want {
		t.Fatalf("expected score %d, got %d", want, a.Score)
	}
}

func TestRiskLevel(t *testing.T) {
	tests := []struct {
		caps []Capability
		want string
	}{
		{[]Capability{CapExec, CapNetwork}, "HIGH"},
		{[]Capability{CapNetwork}, "MEDIUM"},
		{[]Capability{CapFSRead}, "LOW"},
		{[]Capability{}, "LOW"},
	}

	for _, tt := range tests {
		var cs CapabilitySet
		for _, c := range tt.caps {
			cs.Add(c)
		}
		if got := cs.RiskLevel(); got != tt.want {
			t.Errorf("caps %v: expected risk %s, got %s", tt.caps, tt.want, got)
		}
	}
}

func TestCapabilitySetList(t *testing.T) {
	var cs CapabilitySet
	cs.Add(CapFSRead)
	cs.Add(CapExec)

	list := cs.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(list))
	}

	found := make(map[string]bool)
	for _, s := range list {
		found[s] = true
	}
	if !found["fs:read"] || !found["exec"] {
		t.Errorf("unexpected list contents: %v", list)
	}
}

func TestCapabilitySetString(t *testing.T) {
	var cs CapabilitySet
	if cs.String() != "" {
		t.Fatalf("empty set should produce empty string, got %q", cs.String())
	}
}
