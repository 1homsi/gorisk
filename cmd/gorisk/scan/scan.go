package scan

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/health"
	"github.com/1homsi/gorisk/internal/interproc"
	"github.com/1homsi/gorisk/internal/priority"
	"github.com/1homsi/gorisk/internal/report"
	"github.com/1homsi/gorisk/internal/taint"
)

type PolicyException struct {
	Package      string   `json:"package"`
	Capabilities []string `json:"capabilities"`
	Taint        []string `json:"taint"`   // e.g. ["network→exec", "env→exec"]
	Expires      string   `json:"expires"` // ISO 8601 date "2026-06-01"
}

type policy struct {
	Version          int               `json:"version"`
	FailOn           string            `json:"fail_on"`
	MaxHealthScore   int               `json:"max_health_score"`
	MinHealthScore   int               `json:"min_health_score"`
	BlockArchived    bool              `json:"block_archived"`
	DenyCapabilities []string          `json:"deny_capabilities"`
	AllowExceptions  []PolicyException `json:"allow_exceptions"`
	MaxDepDepth      int               `json:"max_dep_depth"`
	ExcludePackages  []string          `json:"exclude_packages"`
}

type exceptionStats struct {
	Applied         int
	Expired         int
	TaintSuppressed int
}

// buildExceptions processes policy exceptions with validation.
// Returns:
//   - exceptions: pkg → capability → bool (for capability exceptions)
//   - taintExceptions: pkg → "source→sink" → bool (for taint exceptions)
//   - stats: exception statistics for reporting
func buildExceptions(allowExceptions []PolicyException) (
	map[string]map[string]bool,
	map[string]map[string]bool,
	exceptionStats,
) {
	now := time.Now()
	exceptions := make(map[string]map[string]bool)
	taintExceptions := make(map[string]map[string]bool)
	var stats exceptionStats

	for _, ex := range allowExceptions {
		// Check expiry
		expired := false
		if ex.Expires != "" {
			expiryDate, err := time.Parse("2006-01-02", ex.Expires)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] exception for %s has invalid expiry date %q\n", ex.Package, ex.Expires)
				continue
			}
			if now.After(expiryDate) {
				fmt.Fprintf(os.Stderr, "[WARN] exception for %s expired on %s\n", ex.Package, ex.Expires)
				stats.Expired++
				expired = true
			}
		}

		// Don't apply expired exceptions
		if expired {
			continue
		}

		// Track if this exception was applied
		applied := false

		// Add capability exceptions (merge if package already has exceptions)
		if len(ex.Capabilities) > 0 {
			caps, ok := exceptions[ex.Package]
			if !ok {
				caps = make(map[string]bool)
				exceptions[ex.Package] = caps
			}
			for _, c := range ex.Capabilities {
				caps[strings.ToLower(c)] = true
			}
			applied = true
		}

		// Add taint exceptions (merge if package already has exceptions)
		if len(ex.Taint) > 0 {
			taints, ok := taintExceptions[ex.Package]
			if !ok {
				taints = make(map[string]bool)
				taintExceptions[ex.Package] = taints
			}
			for _, t := range ex.Taint {
				taints[t] = true
			}
			stats.TaintSuppressed += len(ex.Taint)
			applied = true
		}

		if applied {
			stats.Applied++
		}
	}

	return exceptions, taintExceptions, stats
}

// filterTaintFindings removes taint findings that are suppressed by policy exceptions.
func filterTaintFindings(findings []taint.TaintFinding, taintExceptions map[string]map[string]bool) []taint.TaintFinding {
	if len(taintExceptions) == 0 {
		return findings
	}

	filtered := make([]taint.TaintFinding, 0, len(findings))
	for _, f := range findings {
		// Check if this package has taint exceptions
		pkgExceptions, ok := taintExceptions[f.Package]
		if !ok {
			filtered = append(filtered, f)
			continue
		}

		// Build the source→sink key
		key := f.Source + "→" + f.Sink
		if !pkgExceptions[key] {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// writeExceptionSummary outputs a summary of policy exceptions applied.
func writeExceptionSummary(w *os.File, stats exceptionStats) {
	fmt.Fprintf(w, "=== Policy Exceptions ===\n")
	fmt.Fprintf(w, "Applied: %d\n", stats.Applied)
	if stats.TaintSuppressed > 0 {
		fmt.Fprintf(w, "Taint flows suppressed: %d\n", stats.TaintSuppressed)
	}
	if stats.Expired > 0 {
		fmt.Fprintf(w, "Expired (not applied): %d\n", stats.Expired)
	}
}

func Run(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	sarifOut := fs.Bool("sarif", false, "SARIF 2.1.0 output")
	failOn := fs.String("fail-on", "high", "fail on risk level: low|medium|high")
	policyFile := fs.String("policy", "", "policy JSON file")
	lang := fs.String("lang", "auto", "language analyzer: auto|go|node")
	timings := fs.Bool("timings", false, "print per-phase timing breakdown after output")
	verbose := fs.Bool("verbose", false, "enable verbose debug logging")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	p := policy{FailOn: "high", MaxHealthScore: 30}
	if *policyFile != "" {
		f, err := os.Open(*policyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load policy:", err)
			return 2
		}
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			f.Close()
			fmt.Fprintln(os.Stderr, "parse policy:", err)
			return 2
		}
		f.Close()
		if p.Version != 0 && p.Version != 1 {
			fmt.Fprintf(os.Stderr, "policy: unsupported version %d (supported: 1)\n", p.Version)
			return 2
		}
		if p.FailOn != "" {
			switch p.FailOn {
			case "low", "medium", "high":
				*failOn = p.FailOn
			default:
				fmt.Fprintf(os.Stderr, "policy: fail_on must be low|medium|high, got %q\n", p.FailOn)
				return 2
			}
		}
	}

	excluded := make(map[string]bool, len(p.ExcludePackages))
	for _, pkg := range p.ExcludePackages {
		excluded[pkg] = true
	}

	// Build exceptions with validation
	exceptions, taintExceptions, exceptionStats := buildExceptions(p.AllowExceptions)

	deniedCaps := make(map[string]bool)
	for _, c := range p.DenyCapabilities {
		deniedCaps[strings.ToLower(c)] = true
	}

	a, err := analyzer.ForLang(*lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// Enable verbose logging if requested
	if *verbose {
		interproc.SetVerbose(true)
		taint.SetVerbose(true)
	}

	// Phase: load graph
	t0 := time.Now()
	g, err := a.Load(dir)
	loadDur := time.Since(t0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	// Phase: build capability reports (sorted for determinism)
	t1 := time.Now()
	pkgKeys := make([]string, 0, len(g.Packages))
	for k := range g.Packages {
		pkgKeys = append(pkgKeys, k)
	}
	sort.Strings(pkgKeys)

	var capReports []report.CapabilityReport
	for _, pkgKey := range pkgKeys {
		pkg := g.Packages[pkgKey]
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
	capDur := time.Since(t1)

	// Phase: health scoring
	t2 := time.Now()
	seen := make(map[string]bool)
	var mods []health.ModuleRef
	for _, mod := range g.Modules {
		if mod.Main || seen[mod.Path] {
			continue
		}
		seen[mod.Path] = true
		mods = append(mods, health.ModuleRef{Path: mod.Path, Version: mod.Version})
	}
	healthReports, healthTiming := health.ScoreAll(mods)
	healthDur := time.Since(t2)

	taintFindings := taint.Analyze(g.Packages)

	// Filter taint findings based on exceptions
	filteredTaint := filterTaintFindings(taintFindings, taintExceptions)

	sr := report.ScanReport{
		GraphChecksum: g.Checksum(),
		Capabilities:  capReports,
		Health:        healthReports,
		TaintFindings: filteredTaint,
		Passed:        true,
	}

	failLevel := capability.RiskValue(*failOn)

	// Build module→CVE count map for composite scoring
	moduleCVEs := make(map[string]int)
	for _, hr := range healthReports {
		moduleCVEs[hr.Module] = hr.CVECount
	}

	// Build package→taint findings map for composite scoring
	pkgTaints := make(map[string][]taint.TaintFinding)
	for _, tf := range filteredTaint {
		pkgTaints[tf.Package] = append(pkgTaints[tf.Package], tf)
	}

	for _, cr := range capReports {
		if excluded[cr.Package] {
			continue
		}
		pkg := g.Packages[cr.Package]
		if pkg == nil || pkg.Module == nil {
			continue
		}

		// Compute composite score for this package
		cveCount := 0
		if pkg.Module != nil {
			cveCount = moduleCVEs[pkg.Module.Path]
		}
		compositeScore := priority.Compute(
			cr.Capabilities,
			nil, // reachability unknown for now
			cveCount,
			pkgTaints[cr.Package],
		)

		// Use composite score level for fail evaluation
		if capability.RiskValue(compositeScore.Level) >= failLevel {
			sr.Passed = false
			sr.FailReason = fmt.Sprintf("package %s has %s composite risk (score: %.1f)", cr.Package, compositeScore.Level, compositeScore.Composite)
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

	// Phase: output formatting
	t3 := time.Now()
	var writeErr error
	switch {
	case *sarifOut:
		writeErr = report.WriteScanSARIF(os.Stdout, sr)
	case *jsonOut:
		writeErr = report.WriteScanJSON(os.Stdout, sr)
	default:
		fmt.Fprintf(os.Stdout, "graph checksum: %s\n\n", sr.GraphChecksum)
		report.WriteScan(os.Stdout, sr)
		// Print exception summary if any exceptions were configured
		if exceptionStats.Applied > 0 || exceptionStats.Expired > 0 {
			fmt.Fprintln(os.Stdout)
			writeExceptionSummary(os.Stdout, exceptionStats)
		}
	}
	outDur := time.Since(t3)

	if writeErr != nil {
		fmt.Fprintln(os.Stderr, "write output:", writeErr)
		return 2
	}

	if *timings {
		total := loadDur + capDur + healthDur + outDur
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "=== Timings ===")
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "graph load", fmtDur(loadDur))
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "capability detect", fmtDur(capDur))
		fmt.Fprintf(os.Stdout, "%-25s  %s  (%d modules, %d workers)\n",
			"health scoring", fmtDur(healthDur), healthTiming.ModuleCount, healthTiming.Workers)
		fmt.Fprintf(os.Stdout, "  %-23s  %s  (%d calls)\n", "github API", fmtDur(healthTiming.GithubTime), healthTiming.GithubCalls)
		fmt.Fprintf(os.Stdout, "  %-23s  %s  (%d calls)\n", "osv API", fmtDur(healthTiming.OsvTime), healthTiming.OsvCalls)
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "output formatting", fmtDur(outDur))
		fmt.Fprintln(os.Stdout, strings.Repeat("─", 40))
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "total", fmtDur(total))
	}

	if !sr.Passed {
		return 1
	}
	return 0
}

func fmtDur(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
