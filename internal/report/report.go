package report

import "github.com/1homsi/gorisk/internal/capability"

type CapabilityReport struct {
	Package      string
	Module       string
	Capabilities capability.CapabilitySet
	RiskLevel    string
}

type HealthReport struct {
	Module   string
	Version  string
	Score    int
	Archived bool
	CVECount int
	CVEs     []string
	Signals  map[string]int
}

type UpgradeReport struct {
	Module   string
	OldVer   string
	NewVer   string
	Risk     string
	Breaking []BreakingChange
	NewDeps  []string
}

type BreakingChange struct {
	Kind   string
	Symbol string
	OldSig string
	NewSig string
	UsedIn []string
}

type ImpactReport struct {
	Module           string
	Version          string
	AffectedPackages []string
	AffectedMains    []string
	LOCTouched       int
	Depth            int
}

type ScanReport struct {
	GraphChecksum string `json:"graph_checksum,omitempty"`
	Capabilities  []CapabilityReport
	Health        []HealthReport
	Passed        bool
	FailReason    string
}
