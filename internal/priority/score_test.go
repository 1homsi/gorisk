package priority

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/taint"
)

func TestComputeBaseScore(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec) // exec = 20

	score := Compute(caps, nil, 0, nil)

	if score.CapabilityScore != 20 {
		t.Errorf("expected CapabilityScore 20, got %.2f", score.CapabilityScore)
	}
	if score.ReachabilityMod != 1.0 {
		t.Errorf("expected ReachabilityMod 1.0 (unknown), got %.2f", score.ReachabilityMod)
	}
	if score.CVEMod != 1.0 {
		t.Errorf("expected CVEMod 1.0, got %.2f", score.CVEMod)
	}
	if score.TaintMod != 1.0 {
		t.Errorf("expected TaintMod 1.0, got %.2f", score.TaintMod)
	}
	if score.Composite != 20 {
		t.Errorf("expected Composite 20, got %.2f", score.Composite)
	}
	if score.Level != "MEDIUM" {
		t.Errorf("expected Level MEDIUM, got %s", score.Level)
	}
}

func TestComputeReachable(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec) // exec = 20

	reachable := true
	score := Compute(caps, &reachable, 0, nil)

	if score.ReachabilityMod != 1.3 {
		t.Errorf("expected ReachabilityMod 1.3 (reachable), got %.2f", score.ReachabilityMod)
	}
	// 20 × 1.3 = 26
	if score.Composite != 26 {
		t.Errorf("expected Composite 26, got %.2f", score.Composite)
	}
}

func TestComputeUnreachable(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec) // exec = 20

	reachable := false
	score := Compute(caps, &reachable, 0, nil)

	if score.ReachabilityMod != 0.5 {
		t.Errorf("expected ReachabilityMod 0.5 (unreachable), got %.2f", score.ReachabilityMod)
	}
	// 20 × 0.5 = 10
	if score.Composite != 10 {
		t.Errorf("expected Composite 10, got %.2f", score.Composite)
	}
	if score.Level != "MEDIUM" {
		t.Errorf("expected Level MEDIUM, got %s", score.Level)
	}
}

func TestComputeCVEs(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec) // exec = 20

	score := Compute(caps, nil, 2, nil)

	// CVEMod = 1.0 + (2 × 0.3) = 1.6
	expected := 1.6
	if score.CVEMod != expected {
		t.Errorf("expected CVEMod %.2f, got %.2f", expected, score.CVEMod)
	}
	// 20 × 1.6 = 32
	if score.Composite != 32 {
		t.Errorf("expected Composite 32, got %.2f", score.Composite)
	}
	if score.Level != "HIGH" {
		t.Errorf("expected Level HIGH, got %s", score.Level)
	}
}

func TestComputeCVEsCapped(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec) // exec = 20

	// Many CVEs should cap at 2.0
	score := Compute(caps, nil, 10, nil)

	if score.CVEMod != 2.0 {
		t.Errorf("expected CVEMod capped at 2.0, got %.2f", score.CVEMod)
	}
	// 20 × 2.0 = 40
	if score.Composite != 40 {
		t.Errorf("expected Composite 40, got %.2f", score.Composite)
	}
}

func TestComputeTaint(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec) // exec = 20

	taintFindings := []taint.TaintFinding{
		{Risk: "HIGH"},
		{Risk: "MEDIUM"},
	}

	score := Compute(caps, nil, 0, taintFindings)

	// TaintMod = 1.0 + 0.25 + 0.15 = 1.4
	expected := 1.4
	if score.TaintMod != expected {
		t.Errorf("expected TaintMod %.2f, got %.2f", expected, score.TaintMod)
	}
	// 20 × 1.4 = 28
	if score.Composite != 28 {
		t.Errorf("expected Composite 28, got %.2f", score.Composite)
	}
}

func TestComputeAllModifiers(t *testing.T) {
	var caps capability.CapabilitySet
	caps.Add(capability.CapExec)    // exec = 20
	caps.Add(capability.CapUnsafe)  // unsafe = 25
	caps.Add(capability.CapNetwork) // network = 15
	// Total = 60

	reachable := true
	taintFindings := []taint.TaintFinding{
		{Risk: "HIGH"},
	}

	score := Compute(caps, &reachable, 1, taintFindings)

	if score.CapabilityScore != 60 {
		t.Errorf("expected CapabilityScore 60, got %.2f", score.CapabilityScore)
	}
	if score.ReachabilityMod != 1.3 {
		t.Errorf("expected ReachabilityMod 1.3, got %.2f", score.ReachabilityMod)
	}
	if score.CVEMod != 1.3 { // 1.0 + 0.3
		t.Errorf("expected CVEMod 1.3, got %.2f", score.CVEMod)
	}
	if score.TaintMod != 1.25 { // 1.0 + 0.25
		t.Errorf("expected TaintMod 1.25, got %.2f", score.TaintMod)
	}

	// Composite = 60 × 1.3 × 1.3 × 1.25 = 126.75, capped at 100
	if score.Composite != 100 {
		t.Errorf("expected Composite capped at 100, got %.2f", score.Composite)
	}
	if score.Level != "HIGH" {
		t.Errorf("expected Level HIGH, got %s", score.Level)
	}
}

func TestDeriveLevelLow(t *testing.T) {
	level := deriveLevel(5)
	if level != "LOW" {
		t.Errorf("expected LOW, got %s", level)
	}
}

func TestDeriveLevelMedium(t *testing.T) {
	level := deriveLevel(15)
	if level != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", level)
	}
}

func TestDeriveLevelHigh(t *testing.T) {
	level := deriveLevel(35)
	if level != "HIGH" {
		t.Errorf("expected HIGH, got %s", level)
	}
}
