package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/report"
)

type BOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Component struct {
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PackageURL string        `json:"purl,omitempty"`
	Properties []BOMProperty `json:"properties,omitempty"`
}

type BOMTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type BOMMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []BOMTool `json:"tools"`
}

type BOM struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    BOMMetadata `json:"metadata"`
	Components  []Component `json:"components"`
}

func Generate(g *graph.DependencyGraph, capReports []report.CapabilityReport, healthReports []report.HealthReport) BOM {
	capsByModule := make(map[string][]string)
	riskByModule := make(map[string]string)
	for _, cr := range capReports {
		if cr.Module != "" {
			caps := cr.Capabilities.List()
			if len(caps) > 0 {
				capsByModule[cr.Module] = append(capsByModule[cr.Module], caps...)
			}
			if existing, ok := riskByModule[cr.Module]; !ok || riskValue(cr.RiskLevel) > riskValue(existing) {
				riskByModule[cr.Module] = cr.RiskLevel
			}
		}
	}

	healthByModule := make(map[string]int)
	for _, hr := range healthReports {
		healthByModule[hr.Module] = hr.Score
	}

	var components []Component
	for _, mod := range g.Modules {
		if mod.Main {
			continue
		}

		var props []BOMProperty

		if caps, ok := capsByModule[mod.Path]; ok {
			unique := dedupe(caps)
			props = append(props, BOMProperty{
				Name:  "gorisk:capabilities",
				Value: strings.Join(unique, ", "),
			})
		}

		if risk, ok := riskByModule[mod.Path]; ok {
			props = append(props, BOMProperty{
				Name:  "gorisk:risk_level",
				Value: risk,
			})
		}

		if score, ok := healthByModule[mod.Path]; ok {
			props = append(props, BOMProperty{
				Name:  "gorisk:health_score",
				Value: fmt.Sprintf("%d", score),
			})
		}

		purl := ""
		if mod.Version != "" {
			purl = "pkg:golang/" + mod.Path + "@" + mod.Version
		}

		components = append(components, Component{
			Type:       "library",
			Name:       mod.Path,
			Version:    mod.Version,
			PackageURL: purl,
			Properties: props,
		})
	}

	if components == nil {
		components = []Component{}
	}

	return BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: BOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []BOMTool{
				{Name: "gorisk", Version: "dev"},
			},
		},
		Components: components,
	}
}

func riskValue(level string) int {
	switch level {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	default:
		return 1
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
