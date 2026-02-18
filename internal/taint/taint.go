// Package taint identifies packages that act as source→sink conduits —
// the highest-signal supply-chain finding: capabilities that both receive
// untrusted input and perform a dangerous operation.
package taint

import (
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// TaintFinding records a single source→sink capability pair detected in a package.
type TaintFinding struct {
	Package string                `json:"package"`
	Module  string                `json:"module,omitempty"`
	Source  capability.Capability `json:"source"`
	Sink    capability.Capability `json:"sink"`
	Risk    string                `json:"risk"`
	Note    string                `json:"note"`
}

type taintRule struct {
	Source capability.Capability
	Sink   capability.Capability
	Risk   string
	Note   string
}

// taintRules defines the dangerous source→sink pairs to detect.
var taintRules = []taintRule{
	{capability.CapEnv, capability.CapExec, "HIGH", "env var → exec — injection risk"},
	{capability.CapNetwork, capability.CapExec, "HIGH", "network input → exec — RCE risk"},
	{capability.CapFSRead, capability.CapExec, "HIGH", "file content → exec injection"},
	{capability.CapNetwork, capability.CapUnsafe, "HIGH", "network-controlled memory"},
	{capability.CapNetwork, capability.CapFSWrite, "MEDIUM", "network data written to disk"},
	{capability.CapFSRead, capability.CapNetwork, "MEDIUM", "file content exfiltration"},
	{capability.CapEnv, capability.CapFSWrite, "LOW", "env expansion in file path"},
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
				findings = append(findings, TaintFinding{
					Package: pkg.ImportPath,
					Module:  modPath,
					Source:  rule.Source,
					Sink:    rule.Sink,
					Risk:    rule.Risk,
					Note:    rule.Note,
				})
			}
		}
	}

	// Sort: HIGH first, then MEDIUM, then LOW; within risk level sort by package.
	sortFindings(findings)
	return findings
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
