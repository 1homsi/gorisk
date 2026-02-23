package report

import (
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/engines/integrity"
	"github.com/1homsi/gorisk/internal/engines/topology"
	"github.com/1homsi/gorisk/internal/engines/versiondiff"
	"github.com/1homsi/gorisk/internal/taint"
)

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
	SchemaVersion string `json:"schema_version,omitempty"`
	GraphChecksum string `json:"graph_checksum,omitempty"`
	Capabilities  []CapabilityReport
	Health        []HealthReport             // only populated with --online
	TaintFindings []taint.TaintFinding       `json:"taint_findings,omitempty"`
	Topology      *topology.TopologyReport   `json:"topology,omitempty"`
	Integrity     *integrity.IntegrityReport `json:"integrity,omitempty"`
	VersionDiff   *versiondiff.DiffReport    `json:"version_diff,omitempty"`
	Passed        bool
	FailReason    string
}
