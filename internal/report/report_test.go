package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/taint"
)

func TestWriteCapabilitiesJSON(t *testing.T) {
	reports := []CapabilityReport{
		{
			Package:   "test/pkg",
			Module:    "test",
			RiskLevel: "HIGH",
			Capabilities: capability.CapabilitySet{
				Score: 25,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteCapabilitiesJSON(&buf, reports)
	if err != nil {
		t.Fatalf("WriteCapabilitiesJSON() error = %v", err)
	}

	// Verify JSON is valid
	var decoded []CapabilityReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if len(decoded) != 1 {
		t.Errorf("Expected 1 report, got %d", len(decoded))
	}
	if decoded[0].Package != "test/pkg" {
		t.Errorf("Package = %q, want %q", decoded[0].Package, "test/pkg")
	}
}

func TestWriteHealthJSON(t *testing.T) {
	reports := []HealthReport{
		{
			Module:   "test",
			Version:  "v1.0.0",
			Score:    100,
			CVECount: 0,
			CVEs:     []string{},
			Signals:  map[string]int{"cve_count": 0},
		},
	}

	var buf bytes.Buffer
	err := WriteHealthJSON(&buf, reports)
	if err != nil {
		t.Fatalf("WriteHealthJSON() error = %v", err)
	}

	// Verify JSON is valid
	var decoded []HealthReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if len(decoded) != 1 {
		t.Errorf("Expected 1 report, got %d", len(decoded))
	}
	if decoded[0].Module != "test" {
		t.Errorf("Module = %q, want %q", decoded[0].Module, "test")
	}
}

func TestWriteUpgradeJSON(t *testing.T) {
	report := UpgradeReport{
		Module: "test",
		OldVer: "v1.0.0",
		NewVer: "v2.0.0",
		Risk:   "HIGH",
		Breaking: []BreakingChange{
			{
				Kind:   "function",
				Symbol: "DoSomething",
				OldSig: "func()",
				NewSig: "func(int)",
			},
		},
		NewDeps: []string{"new/dep"},
	}

	var buf bytes.Buffer
	err := WriteUpgradeJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteUpgradeJSON() error = %v", err)
	}

	// Verify JSON is valid
	var decoded UpgradeReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.Module != "test" {
		t.Errorf("Module = %q, want %q", decoded.Module, "test")
	}
	if len(decoded.Breaking) != 1 {
		t.Errorf("Expected 1 breaking change, got %d", len(decoded.Breaking))
	}
}

func TestWriteImpactJSON(t *testing.T) {
	report := ImpactReport{
		Module:           "test",
		Version:          "v1.0.0",
		AffectedPackages: []string{"pkg1", "pkg2"},
		AffectedMains:    []string{"cmd/main"},
		LOCTouched:       100,
		Depth:            2,
	}

	var buf bytes.Buffer
	err := WriteImpactJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteImpactJSON() error = %v", err)
	}

	// Verify JSON is valid
	var decoded ImpactReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.Module != "test" {
		t.Errorf("Module = %q, want %q", decoded.Module, "test")
	}
	if decoded.Depth != 2 {
		t.Errorf("Depth = %d, want %d", decoded.Depth, 2)
	}
}

func TestWriteScanJSON(t *testing.T) {
	report := ScanReport{
		GraphChecksum: "abc123",
		Capabilities: []CapabilityReport{
			{Package: "test", Module: "test", RiskLevel: "LOW"},
		},
		Health: []HealthReport{
			{Module: "test", Score: 100},
		},
		TaintFindings: []taint.TaintFinding{
			{Package: "test", Source: "network", Sink: "exec", Risk: "HIGH"},
		},
		Passed:     true,
		FailReason: "",
	}

	var buf bytes.Buffer
	err := WriteScanJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteScanJSON() error = %v", err)
	}

	// Verify JSON is valid
	var decoded ScanReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.GraphChecksum != "abc123" {
		t.Errorf("GraphChecksum = %q, want %q", decoded.GraphChecksum, "abc123")
	}
	if !decoded.Passed {
		t.Error("Expected Passed = true")
	}
	if len(decoded.TaintFindings) != 1 {
		t.Errorf("Expected 1 taint finding, got %d", len(decoded.TaintFindings))
	}
}

func TestWriteCapDiff(t *testing.T) {
	tests := []struct {
		name     string
		report   CapDiffReport
		wantText []string
	}{
		{
			name: "no changes",
			report: CapDiffReport{
				Module:     "test",
				OldVersion: "v1.0.0",
				NewVersion: "v1.0.1",
				Diffs:      []PackageCapDiff{},
			},
			wantText: []string{"Capability Diff", "v1.0.0", "v1.0.1", "No capability changes"},
		},
		{
			name: "with changes",
			report: CapDiffReport{
				Module:     "test",
				OldVersion: "v1.0.0",
				NewVersion: "v2.0.0",
				Diffs: []PackageCapDiff{
					{
						Package:   "test/pkg",
						Added:     []string{"exec"},
						Removed:   []string{"crypto"},
						Escalated: false,
					},
				},
				Escalated: false,
			},
			wantText: []string{"Capability Diff", "v1.0.0", "v2.0.0", "test/pkg", "+ exec", "- crypto"},
		},
		{
			name: "escalated",
			report: CapDiffReport{
				Module:     "test",
				OldVersion: "v1.0.0",
				NewVersion: "v2.0.0",
				Diffs: []PackageCapDiff{
					{
						Package:   "test/pkg",
						Added:     []string{"unsafe"},
						Escalated: true,
					},
				},
				Escalated: true,
			},
			wantText: []string{"Capability Diff", "ESCALATION DETECTED", "+ unsafe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			WriteCapDiff(&buf, tt.report)

			output := buf.String()
			for _, want := range tt.wantText {
				if !strings.Contains(output, want) {
					t.Errorf("Output missing %q\nGot: %s", want, output)
				}
			}
		})
	}
}

func TestWriteCapDiffJSON(t *testing.T) {
	report := CapDiffReport{
		Module:     "test",
		OldVersion: "v1.0.0",
		NewVersion: "v2.0.0",
		Diffs: []PackageCapDiff{
			{
				Package:   "test/pkg",
				Added:     []string{"exec"},
				Removed:   []string{"crypto"},
				Escalated: true,
			},
		},
		Escalated: true,
	}

	var buf bytes.Buffer
	err := WriteCapDiffJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteCapDiffJSON() error = %v", err)
	}

	// Verify JSON is valid
	var decoded CapDiffReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.Module != "test" {
		t.Errorf("Module = %q, want %q", decoded.Module, "test")
	}
	if !decoded.Escalated {
		t.Error("Expected Escalated = true")
	}
	if len(decoded.Diffs) != 1 {
		t.Errorf("Expected 1 diff, got %d", len(decoded.Diffs))
	}
}
