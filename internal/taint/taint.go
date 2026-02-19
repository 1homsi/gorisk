// Package taint identifies packages that act as source→sink conduits —
// the highest-signal supply-chain finding: capabilities that both receive
// untrusted input and perform a dangerous operation.
package taint

import (
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// TaintEvidence represents a single capability in the taint evidence chain.
type TaintEvidence struct {
	Capability capability.Capability `json:"capability"`
	Confidence float64               `json:"confidence"`
}

// TaintFinding records a single source→sink capability pair detected in a package.
type TaintFinding struct {
	Package       string                `json:"package"`
	Module        string                `json:"module,omitempty"`
	Source        capability.Capability `json:"source"`
	Sink          capability.Capability `json:"sink"`
	Risk          string                `json:"risk"`
	Note          string                `json:"note"`
	Confidence    float64               `json:"confidence"`               // min(source_conf, sink_conf)
	EvidenceChain []TaintEvidence       `json:"evidence_chain,omitempty"` // [source_evidence, sink_evidence]

	// Interprocedural fields (optional, populated by interprocedural analysis)
	SourceFunc string   `json:"source_func,omitempty"` // Function where source originates
	SinkFunc   string   `json:"sink_func,omitempty"`   // Function where sink occurs
	CallStack  []string `json:"call_stack,omitempty"`  // Call path from source to sink
}

type taintRule struct {
	Source capability.Capability
	Sink   capability.Capability
	Risk   string
	Note   string
}

// taintRules defines the dangerous source→sink pairs to detect.
var taintRules = []taintRule{
	// Existing rules
	{capability.CapEnv, capability.CapExec, "HIGH", "env var → exec — injection risk"},
	{capability.CapNetwork, capability.CapExec, "HIGH", "network input → exec — RCE risk"},
	{capability.CapFSRead, capability.CapExec, "HIGH", "file content → exec injection"},
	{capability.CapNetwork, capability.CapUnsafe, "HIGH", "network-controlled memory"},
	{capability.CapNetwork, capability.CapFSWrite, "MEDIUM", "network data written to disk"},
	{capability.CapFSRead, capability.CapNetwork, "MEDIUM", "file content exfiltration"},
	{capability.CapEnv, capability.CapFSWrite, "LOW", "env expansion in file path"},

	// New rules for expanded taint analysis
	{capability.CapNetwork, capability.CapPlugin, "HIGH", "remote plugin injection"},
	{capability.CapFSRead, capability.CapPlugin, "HIGH", "dynamic loading from attacker-controlled file"},
	{capability.CapEnv, capability.CapCrypto, "MEDIUM", "env-sourced key material"},
	{capability.CapNetwork, capability.CapReflect, "MEDIUM", "runtime behavior from network"},
	{capability.CapFSRead, capability.CapUnsafe, "HIGH", "attacker-controlled memory ops"},
	{capability.CapEnv, capability.CapNetwork, "MEDIUM", "env-configured exfil endpoint"},
}

// Analyze inspects all packages in the dependency graph and returns a list of
// source→sink taint findings ordered by risk level (HIGH first).
func Analyze(pkgs map[string]*graph.Package) []TaintFinding {
	var findings []TaintFinding

	for _, pkg := range pkgs {
		caps := pkg.Capabilities
		modPath := ""
		if pkg.Module != nil {
			modPath = pkg.Module.Path
		}

		for _, rule := range taintRules {
			if caps.Has(rule.Source) && caps.Has(rule.Sink) {
				// Compute confidence as min(source_conf, sink_conf)
				sourceConf := caps.Confidence(rule.Source)
				sinkConf := caps.Confidence(rule.Sink)
				conf := min(sourceConf, sinkConf)

				// If no evidence recorded, use default confidence of 0
				if conf == 0 {
					conf = 0.0
				}

				// Downgrade severity one level if confidence < 0.70
				risk := rule.Risk
				if conf > 0 && conf < 0.70 {
					risk = downgradeSeverity(risk)
				}

				finding := TaintFinding{
					Package:    pkg.ImportPath,
					Module:     modPath,
					Source:     rule.Source,
					Sink:       rule.Sink,
					Risk:       risk,
					Note:       rule.Note,
					Confidence: conf,
					EvidenceChain: []TaintEvidence{
						{Capability: rule.Source, Confidence: sourceConf},
						{Capability: rule.Sink, Confidence: sinkConf},
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	// Sort: HIGH first, then MEDIUM, then LOW; within risk level sort by package.
	sortFindings(findings)
	return findings
}

// downgradeSeverity downgrades the severity level by one step.
func downgradeSeverity(level string) string {
	switch level {
	case "HIGH":
		return "MEDIUM"
	case "MEDIUM":
		return "LOW"
	default:
		return level
	}
}

// min returns the minimum of two float64 values.
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func sortFindings(findings []TaintFinding) {
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && less(findings[j], findings[j-1]); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

func less(a, b TaintFinding) bool {
	ra, rb := capability.RiskValue(a.Risk), capability.RiskValue(b.Risk)
	if ra != rb {
		return ra > rb // higher risk first
	}
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	return a.Source < b.Source
}
