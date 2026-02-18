package health

import (
	"testing"
	"time"
)

func TestScoreAllEmptyModules(t *testing.T) {
	reports, timing := ScoreAll(nil)
	if reports != nil {
		t.Errorf("expected nil reports for empty input, got %v", reports)
	}
	if timing.Total != 0 {
		t.Errorf("expected zero timing for empty input, got %v", timing.Total)
	}
}

func TestScoreAllReturnsTiming(t *testing.T) {
	// Use a fake/non-existent module to ensure fast path (API calls fail quickly)
	mods := []ModuleRef{
		{Path: "example.com/nonexistent-for-testing-12345", Version: "v1.0.0"},
	}
	reports, timing := ScoreAll(mods)

	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if timing.Total <= 0 {
		t.Errorf("expected positive Total timing, got %v", timing.Total)
	}
	if timing.ModuleCount != 1 {
		t.Errorf("expected ModuleCount=1, got %d", timing.ModuleCount)
	}
	if timing.Workers < 1 {
		t.Errorf("expected Workers>=1, got %d", timing.Workers)
	}
}

func TestScoreAllWorkerCount(t *testing.T) {
	// With fewer modules than default workers, Workers should equal len(mods)
	mods := make([]ModuleRef, 3)
	for i := range mods {
		mods[i] = ModuleRef{Path: "example.com/test", Version: "v1.0.0"}
	}
	_, timing := ScoreAll(mods)
	if timing.Workers != 3 {
		t.Errorf("expected Workers=3 for 3 modules, got %d", timing.Workers)
	}
}

func TestScoreAllParallelTiming(t *testing.T) {
	mods := make([]ModuleRef, 5)
	for i := range mods {
		mods[i] = ModuleRef{Path: "example.com/t", Version: "v1.0.0"}
	}
	start := time.Now()
	reports, timing := ScoreAll(mods)
	elapsed := time.Since(start)

	if len(reports) != 5 {
		t.Fatalf("expected 5 reports, got %d", len(reports))
	}
	// Total timing should be <= actual wall time + some slack
	if timing.Total > elapsed+time.Second {
		t.Errorf("timing.Total=%v exceeds wall time %v", timing.Total, elapsed)
	}
}

func TestHealthTimingFields(t *testing.T) {
	var ht HealthTiming
	if ht.GithubCalls != 0 || ht.OsvCalls != 0 {
		t.Error("zero-value HealthTiming should have zero call counts")
	}
}
