package sbom

import (
	"strings"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/report"
)

func TestGenerate(t *testing.T) {
	g := graph.NewDependencyGraph()

	// Add main module (should be excluded)
	g.Main = &graph.Module{
		Path:    "example.com/myapp",
		Version: "v1.0.0",
		Main:    true,
	}
	g.Modules["example.com/myapp"] = g.Main

	// Add dependency modules
	g.Modules["github.com/foo/bar"] = &graph.Module{
		Path:    "github.com/foo/bar",
		Version: "v1.2.3",
		Main:    false,
	}
	g.Modules["github.com/baz/qux"] = &graph.Module{
		Path:    "github.com/baz/qux",
		Version: "v2.0.0",
		Main:    false,
	}

	// Create capability sets with actual capabilities
	fooBarCaps := capability.CapabilitySet{}
	fooBarCaps.Add(capability.CapExec)
	fooBarCaps.Add(capability.CapNetwork)

	bazQuxCaps := capability.CapabilitySet{}
	bazQuxCaps.Add(capability.CapCrypto)

	capReports := []report.CapabilityReport{
		{
			Module:       "github.com/foo/bar",
			RiskLevel:    "HIGH",
			Capabilities: fooBarCaps,
		},
		{
			Module:       "github.com/baz/qux",
			RiskLevel:    "LOW",
			Capabilities: bazQuxCaps,
		},
	}

	healthReports := []report.HealthReport{
		{Module: "github.com/foo/bar", Score: 85},
		{Module: "github.com/baz/qux", Score: 100},
	}

	bom := Generate(g, capReports, healthReports)

	// Verify BOM metadata
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if bom.SpecVersion != "1.4" {
		t.Errorf("SpecVersion = %q, want %q", bom.SpecVersion, "1.4")
	}
	if len(bom.Metadata.Tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(bom.Metadata.Tools))
	}
	if bom.Metadata.Tools[0].Name != "gorisk" {
		t.Errorf("Tool name = %q, want %q", bom.Metadata.Tools[0].Name, "gorisk")
	}

	// Verify components (should be 2, excluding main module)
	if len(bom.Components) != 2 {
		t.Fatalf("Expected 2 components, got %d", len(bom.Components))
	}

	// Find the foo/bar component
	var fooBar *Component
	for i := range bom.Components {
		if bom.Components[i].Name == "github.com/foo/bar" {
			fooBar = &bom.Components[i]
			break
		}
	}

	if fooBar == nil {
		t.Fatal("Component github.com/foo/bar not found")
	}

	// Verify component fields
	if fooBar.Type != "library" {
		t.Errorf("Component type = %q, want %q", fooBar.Type, "library")
	}
	if fooBar.Version != "v1.2.3" {
		t.Errorf("Component version = %q, want %q", fooBar.Version, "v1.2.3")
	}
	if !strings.Contains(fooBar.PackageURL, "pkg:golang/github.com/foo/bar@v1.2.3") {
		t.Errorf("PackageURL = %q, want to contain pkg:golang/...", fooBar.PackageURL)
	}

	// Verify properties
	var hasCapabilities, hasRisk, hasHealth bool
	for _, prop := range fooBar.Properties {
		switch prop.Name {
		case "gorisk:capabilities":
			hasCapabilities = true
			// Should contain exec and network
			if !strings.Contains(prop.Value, "exec") {
				t.Error("capabilities property missing 'exec'")
			}
		case "gorisk:risk_level":
			hasRisk = true
			if prop.Value != "HIGH" {
				t.Errorf("risk_level = %q, want %q", prop.Value, "HIGH")
			}
		case "gorisk:health_score":
			hasHealth = true
			if prop.Value != "85" {
				t.Errorf("health_score = %q, want %q", prop.Value, "85")
			}
		}
	}

	if !hasCapabilities {
		t.Error("Missing gorisk:capabilities property")
	}
	if !hasRisk {
		t.Error("Missing gorisk:risk_level property")
	}
	if !hasHealth {
		t.Error("Missing gorisk:health_score property")
	}
}

func TestGenerateEmpty(t *testing.T) {
	g := graph.NewDependencyGraph()
	bom := Generate(g, nil, nil)

	// Should return empty components array, not nil
	if bom.Components == nil {
		t.Error("Expected empty Components array, got nil")
	}
	if len(bom.Components) != 0 {
		t.Errorf("Expected 0 components, got %d", len(bom.Components))
	}
}

func TestRiskValue(t *testing.T) {
	tests := []struct {
		level string
		want  int
	}{
		{"HIGH", 3},
		{"MEDIUM", 2},
		{"LOW", 1},
		{"", 1},
		{"UNKNOWN", 1},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			got := riskValue(tt.level)
			if got != tt.want {
				t.Errorf("riskValue(%q) = %d, want %d", tt.level, got, tt.want)
			}
		})
	}
}

func TestDedupe(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "no duplicates",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "with duplicates",
			input: []string{"a", "b", "a", "c", "b"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty",
			input: []string{},
			want:  nil,
		},
		{
			name:  "all same",
			input: []string{"a", "a", "a"},
			want:  []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupe(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("dedupe() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("dedupe()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGenerateRiskPriority(t *testing.T) {
	g := graph.NewDependencyGraph()
	g.Modules["test"] = &graph.Module{Path: "test", Main: false}

	// Add multiple capability reports for same module with different risks
	capReports := []report.CapabilityReport{
		{Module: "test", RiskLevel: "LOW"},
		{Module: "test", RiskLevel: "HIGH"},
		{Module: "test", RiskLevel: "MEDIUM"},
	}

	bom := Generate(g, capReports, nil)

	// Should use highest risk level
	if len(bom.Components) != 1 {
		t.Fatalf("Expected 1 component, got %d", len(bom.Components))
	}

	var riskLevel string
	for _, prop := range bom.Components[0].Properties {
		if prop.Name == "gorisk:risk_level" {
			riskLevel = prop.Value
			break
		}
	}

	if riskLevel != "HIGH" {
		t.Errorf("risk_level = %q, want %q (should prioritize highest risk)", riskLevel, "HIGH")
	}
}
