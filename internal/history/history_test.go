package history

import (
	"testing"
)

func TestRecordAndLoad(t *testing.T) {
	dir := t.TempDir()
	h, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Snapshots) != 0 {
		t.Fatalf("expected empty history, got %d snapshots", len(h.Snapshots))
	}

	snap := Snapshot{
		Commit: "abc1234",
		Modules: []ModuleSnapshot{
			{Module: "example.com/a", Version: "v1.0.0", RiskLevel: "HIGH", EffectiveScore: 45},
		},
	}
	h.Record(snap)
	if err := h.Save(dir); err != nil {
		t.Fatal(err)
	}

	h2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(h2.Snapshots) != 1 {
		t.Fatalf("expected 1 snapshot after reload, got %d", len(h2.Snapshots))
	}
	if h2.Snapshots[0].Commit != "abc1234" {
		t.Errorf("unexpected commit: %q", h2.Snapshots[0].Commit)
	}
	if h2.Snapshots[0].Timestamp == "" {
		t.Error("Timestamp should be auto-set by Record()")
	}
}

func TestRecordCapsAt100(t *testing.T) {
	dir := t.TempDir()
	h := &History{}
	for i := 0; i < 110; i++ {
		h.Record(Snapshot{})
	}
	if len(h.Snapshots) != 100 {
		t.Errorf("expected max 100 snapshots, got %d", len(h.Snapshots))
	}
	if err := h.Save(dir); err != nil {
		t.Fatal(err)
	}
}

func TestDiffAdded(t *testing.T) {
	old := Snapshot{Modules: []ModuleSnapshot{}}
	cur := Snapshot{Modules: []ModuleSnapshot{
		{Module: "example.com/new", RiskLevel: "HIGH"},
	}}
	diffs := Diff(old, cur)
	if len(diffs) != 1 || diffs[0].Change != "added" {
		t.Errorf("expected 1 added diff, got: %+v", diffs)
	}
}

func TestDiffRemoved(t *testing.T) {
	old := Snapshot{Modules: []ModuleSnapshot{
		{Module: "example.com/old", RiskLevel: "LOW"},
	}}
	cur := Snapshot{Modules: []ModuleSnapshot{}}
	diffs := Diff(old, cur)
	if len(diffs) != 1 || diffs[0].Change != "removed" {
		t.Errorf("expected 1 removed diff, got: %+v", diffs)
	}
}

func TestDiffEscalated(t *testing.T) {
	old := Snapshot{Modules: []ModuleSnapshot{
		{Module: "example.com/dep", RiskLevel: "LOW", EffectiveScore: 5},
	}}
	cur := Snapshot{Modules: []ModuleSnapshot{
		{Module: "example.com/dep", RiskLevel: "HIGH", EffectiveScore: 45},
	}}
	diffs := Diff(old, cur)
	escalated := 0
	for _, d := range diffs {
		if d.Change == "escalated" {
			escalated++
		}
	}
	if escalated != 1 {
		t.Errorf("expected 1 escalated diff, got: %+v", diffs)
	}
}

func TestDiffImproved(t *testing.T) {
	old := Snapshot{Modules: []ModuleSnapshot{
		{Module: "example.com/dep", RiskLevel: "HIGH", EffectiveScore: 45},
	}}
	cur := Snapshot{Modules: []ModuleSnapshot{
		{Module: "example.com/dep", RiskLevel: "LOW", EffectiveScore: 5},
	}}
	diffs := Diff(old, cur)
	improved := 0
	for _, d := range diffs {
		if d.Change == "improved" {
			improved++
		}
	}
	if improved != 1 {
		t.Errorf("expected 1 improved diff, got: %+v", diffs)
	}
}

func TestDiffUnchanged(t *testing.T) {
	mod := ModuleSnapshot{Module: "example.com/same", RiskLevel: "MEDIUM", EffectiveScore: 20}
	old := Snapshot{Modules: []ModuleSnapshot{mod}}
	cur := Snapshot{Modules: []ModuleSnapshot{mod}}
	diffs := Diff(old, cur)
	for _, d := range diffs {
		if d.Change != "unchanged" {
			t.Errorf("expected unchanged, got %q for %s", d.Change, d.Module)
		}
	}
}
