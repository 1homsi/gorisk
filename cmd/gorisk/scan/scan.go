package scan

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/health"
	"github.com/1homsi/gorisk/internal/report"
)

type PolicyException struct {
	Package      string   `json:"package"`
	Capabilities []string `json:"capabilities"`
}

type policy struct {
	FailOn           string            `json:"fail_on"`
	MaxHealthScore   int               `json:"max_health_score"`
	MinHealthScore   int               `json:"min_health_score"`
	BlockArchived    bool              `json:"block_archived"`
	DenyCapabilities []string          `json:"deny_capabilities"`
	AllowExceptions  []PolicyException `json:"allow_exceptions"`
	MaxDepDepth      int               `json:"max_dep_depth"`
	ExcludePackages  []string          `json:"exclude_packages"`
}

func Run(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	sarifOut := fs.Bool("sarif", false, "SARIF 2.1.0 output")
	failOn := fs.String("fail-on", "high", "fail on risk level: low|medium|high")
	policyFile := fs.String("policy", "", "policy JSON file")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	p := policy{FailOn: "high", MaxHealthScore: 30}
	if *policyFile != "" {
		data, err := os.ReadFile(*policyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load policy:", err)
			return 2
		}
		if err := json.Unmarshal(data, &p); err != nil {
			fmt.Fprintln(os.Stderr, "parse policy:", err)
			return 2
		}
		if p.FailOn != "" {
			*failOn = p.FailOn
		}
	}

	excluded := make(map[string]bool, len(p.ExcludePackages))
	for _, pkg := range p.ExcludePackages {
		excluded[pkg] = true
	}

	exceptions := make(map[string]map[string]bool)
	for _, ex := range p.AllowExceptions {
		caps := make(map[string]bool)
		for _, c := range ex.Capabilities {
			caps[strings.ToLower(c)] = true
		}
		exceptions[ex.Package] = caps
	}

	deniedCaps := make(map[string]bool)
	for _, c := range p.DenyCapabilities {
		deniedCaps[strings.ToLower(c)] = true
	}

	g, err := graph.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	var capReports []report.CapabilityReport
	for _, pkg := range g.Packages {
		riskLevel := pkg.Capabilities.RiskLevel()
		modPath := ""
		if pkg.Module != nil {
			modPath = pkg.Module.Path
		}
		capReports = append(capReports, report.CapabilityReport{
			Package:      pkg.ImportPath,
			Module:       modPath,
			Capabilities: pkg.Capabilities,
			RiskLevel:    riskLevel,
		})
	}

	var healthReports []report.HealthReport
	seen := make(map[string]bool)
	for _, mod := range g.Modules {
		if mod.Main || seen[mod.Path] {
			continue
		}
		seen[mod.Path] = true
		hr := health.Score(mod.Path, mod.Version)
		healthReports = append(healthReports, hr)
	}

	sr := report.ScanReport{
		Capabilities: capReports,
		Health:       healthReports,
		Passed:       true,
	}

	failLevel := riskValue(*failOn)

	for _, cr := range capReports {
		if excluded[cr.Package] {
			continue
		}
		pkg := g.Packages[cr.Package]
		if pkg == nil || pkg.Module == nil || !pkg.Module.Main {
			continue
		}

		if riskValue(cr.RiskLevel) >= failLevel {
			sr.Passed = false
			sr.FailReason = fmt.Sprintf("package %s has %s risk capabilities", cr.Package, cr.RiskLevel)
			break
		}

		if len(deniedCaps) > 0 {
			exCaps := exceptions[cr.Package]
			for _, capName := range cr.Capabilities.List() {
				if deniedCaps[strings.ToLower(capName)] && !exCaps[strings.ToLower(capName)] {
					sr.Passed = false
					sr.FailReason = fmt.Sprintf("package %s uses denied capability: %s", cr.Package, capName)
					break
				}
			}
			if !sr.Passed {
				break
			}
		}
	}

	if sr.Passed {
		for _, hr := range healthReports {
			if p.BlockArchived && hr.Archived {
				sr.Passed = false
				sr.FailReason = fmt.Sprintf("module %s is archived", hr.Module)
				break
			}
			if p.MinHealthScore > 0 && hr.Score < p.MinHealthScore {
				sr.Passed = false
				sr.FailReason = fmt.Sprintf("module %s health score %d is below minimum %d", hr.Module, hr.Score, p.MinHealthScore)
				break
			}
		}
	}

	var writeErr error
	switch {
	case *sarifOut:
		writeErr = report.WriteScanSARIF(os.Stdout, sr)
	case *jsonOut:
		writeErr = report.WriteScanJSON(os.Stdout, sr)
	default:
		report.WriteScan(os.Stdout, sr)
	}
	if writeErr != nil {
		fmt.Fprintln(os.Stderr, "write output:", writeErr)
		return 2
	}

	if !sr.Passed {
		return 1
	}
	return 0
}

func riskValue(level string) int {
	switch strings.ToLower(level) {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
