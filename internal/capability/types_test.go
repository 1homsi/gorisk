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

func TestAddWithEvidence(t *testing.T) {
	var cs CapabilitySet
	ev := CapabilityEvidence{
		File:       "foo.go",
		Line:       42,
		Context:    `import "os/exec"`,
		Via:        "import",
		Confidence: 0.90,
	}
	cs.AddWithEvidence(CapExec, ev)

	if !cs.Has(CapExec) {
		t.Fatal("expected CapExec to be set after AddWithEvidence")
	}
	if cs.Score != capWeights[CapExec] {
		t.Fatalf("expected score %d, got %d", capWeights[CapExec], cs.Score)
	}
	evs, ok := cs.Evidence[CapExec]
	if !ok || len(evs) != 1 {
		t.Fatalf("expected 1 evidence entry, got %v", cs.Evidence)
	}
	if evs[0].File != "foo.go" || evs[0].Line != 42 || evs[0].Via != "import" {
		t.Errorf("unexpected evidence: %+v", evs[0])
	}
}

func TestAddWithEvidenceDeduplicatesCaps(t *testing.T) {
	var cs CapabilitySet
	ev1 := CapabilityEvidence{File: "a.go", Line: 1, Via: "import", Confidence: 0.90}
	ev2 := CapabilityEvidence{File: "b.go", Line: 2, Via: "callSite", Confidence: 0.60}

	cs.AddWithEvidence(CapExec, ev1)
	cs.AddWithEvidence(CapExec, ev2) // same cap, different evidence

	if cs.Score != capWeights[CapExec] {
		t.Fatalf("score should not increase for duplicate cap; got %d", cs.Score)
	}
	if len(cs.Evidence[CapExec]) != 2 {
		t.Fatalf("expected 2 evidence entries, got %d", len(cs.Evidence[CapExec]))
	}
}

func TestAddWithEvidenceNoEvidenceSkip(t *testing.T) {
	var cs CapabilitySet
	// Zero-value evidence should not create an Evidence map entry
	cs.AddWithEvidence(CapFSRead, CapabilityEvidence{})
	if cs.Evidence != nil {
		t.Errorf("zero-value evidence should not allocate Evidence map, got: %v", cs.Evidence)
	}
}

func TestMergeWithEvidence(t *testing.T) {
	var a, b CapabilitySet
	a.AddWithEvidence(CapExec, CapabilityEvidence{File: "a.go", Via: "import", Confidence: 0.90})
	b.AddWithEvidence(CapExec, CapabilityEvidence{File: "b.go", Via: "callSite", Confidence: 0.60})
	b.AddWithEvidence(CapNetwork, CapabilityEvidence{File: "b.go", Via: "import", Confidence: 0.90})

	a.MergeWithEvidence(b)

	if !a.Has(CapExec) || !a.Has(CapNetwork) {
		t.Fatal("merged set missing capabilities")
	}
	// exec has evidence from both a.go and b.go
	if len(a.Evidence[CapExec]) != 2 {
		t.Fatalf("expected 2 exec evidence entries after merge, got %d", len(a.Evidence[CapExec]))
	}
	if len(a.Evidence[CapNetwork]) != 1 {
		t.Fatalf("expected 1 network evidence entry, got %d", len(a.Evidence[CapNetwork]))
	}
}

func TestConfidence(t *testing.T) {
	var cs CapabilitySet
	cs.AddWithEvidence(CapExec, CapabilityEvidence{File: "a.go", Via: "import", Confidence: 0.90})
	cs.AddWithEvidence(CapExec, CapabilityEvidence{File: "b.go", Via: "callSite", Confidence: 0.60})

	got := cs.Confidence(CapExec)
	want := (0.90 + 0.60) / 2
	if got != want {
		t.Errorf("expected confidence %.2f, got %.2f", want, got)
	}
}

func TestConfidenceNoEvidence(t *testing.T) {
	var cs CapabilitySet
	cs.Add(CapExec) // no evidence
	if cs.Confidence(CapExec) != 0 {
		t.Errorf("expected confidence 0 with no evidence, got %f", cs.Confidence(CapExec))
	}
}

func TestAddKeepsBackwardCompat(t *testing.T) {
	// Add() must still work exactly as before — no evidence, score accumulates once
	var cs CapabilitySet
	cs.Add(CapFSRead)
	cs.Add(CapFSRead) // duplicate

	if cs.Score != capWeights[CapFSRead] {
		t.Fatalf("Add() score wrong: got %d", cs.Score)
	}
	if cs.Evidence != nil {
		t.Errorf("Add() should not allocate Evidence map")
	}
}
