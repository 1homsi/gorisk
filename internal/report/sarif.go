package report

import (
	"encoding/json"
	"fmt"
	"io"
)

type sarifOutput struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func WriteScanSARIF(w io.Writer, r ScanReport) error {
	rules := []sarifRule{
		{ID: "GORISK001", Name: "HighRiskCapability", ShortDescription: sarifMessage{Text: "Package has high-risk capabilities"}},
		{ID: "GORISK002", Name: "UnhealthyDependency", ShortDescription: sarifMessage{Text: "Dependency has poor health score"}},
	}

	var results []sarifResult

	for _, cr := range r.Capabilities {
		if cr.RiskLevel != "HIGH" {
			continue
		}
		results = append(results, sarifResult{
			RuleID: "GORISK001",
			Level:  "error",
			Message: sarifMessage{
				Text: fmt.Sprintf("Package %s has HIGH risk capabilities: %s (score=%d)",
					cr.Package, cr.Capabilities.String(), cr.Capabilities.Score),
			},
		})
	}

	for _, hr := range r.Health {
		if hr.Score >= 40 {
			continue
		}
		results = append(results, sarifResult{
			RuleID: "GORISK002",
			Level:  "warning",
			Message: sarifMessage{
				Text: fmt.Sprintf("Module %s has low health score: %d", hr.Module, hr.Score),
			},
		})
	}

	out := sarifOutput{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "gorisk",
						Version:        "0.1.0",
						InformationURI: "https://github.com/1homsi/gorisk",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
