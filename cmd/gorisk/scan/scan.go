package scan

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/engines/integrity"
	"github.com/1homsi/gorisk/internal/engines/topology"
	"github.com/1homsi/gorisk/internal/engines/versiondiff"
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

		if expired {
			continue
		}

		applied := false

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

// filterTaintFindings removes taint findings suppressed by policy exceptions.
func filterTaintFindings(findings []taint.TaintFinding, taintExceptions map[string]map[string]bool) []taint.TaintFinding {
	if len(taintExceptions) == 0 {
		return findings
	}

	filtered := make([]taint.TaintFinding, 0, len(findings))
	for _, f := range findings {
		pkgExceptions, ok := taintExceptions[f.Package]
		if !ok {
			filtered = append(filtered, f)
			continue
		}
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
	online := fs.Bool("online", false, "enable health/CVE scoring via GitHub and OSV APIs")
	base := fs.String("base", "", "compare against this git ref or lockfile path for diff-risk scoring")
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

	// Phase: run engines concurrently
	t2 := time.Now()

	var (
		topoReport  topology.TopologyReport
		integReport integrity.IntegrityReport
		diffReport  versiondiff.DiffReport
		wg          sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		if tr, err := topology.Compute(dir, *lang); err == nil {
			topoReport = tr
		}
	}()
	go func() {
		defer wg.Done()
		if ir, err := integrity.Check(dir, *lang); err == nil {
			integReport = ir
		}
	}()
	if *base != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if dr, err := versiondiff.Compute(dir, *base, *lang); err == nil {
				diffReport = dr
			}
		}()
	}

	// Health scoring: only when --online
	var healthReports []report.HealthReport
	var healthTiming health.HealthTiming
	if *online {
		seen := make(map[string]bool)
		var mods []health.ModuleRef
		for _, mod := range g.Modules {
			if mod.Main || seen[mod.Path] {
				continue
			}
			seen[mod.Path] = true
			mods = append(mods, health.ModuleRef{Path: mod.Path, Version: mod.Version})
		}
		healthReports, healthTiming = health.ScoreAll(mods)
	}

	wg.Wait()
	engineDur := time.Since(t2)

	taintFindings := taint.Analyze(g.Packages)
	filteredTaint := filterTaintFindings(taintFindings, taintExceptions)

	sr := report.ScanReport{
		GraphChecksum: g.Checksum(),
		Capabilities:  capReports,
		Health:        healthReports,
		TaintFindings: filteredTaint,
		Topology:      &topoReport,
		Integrity:     &integReport,
		Passed:        true,
	}
	if *base != "" {
		sr.VersionDiff = &diffReport
	}

	failLevel := capability.RiskValue(*failOn)

	// Build module→CVE count map (only used when --online)
	moduleCVEs := make(map[string]int)
	for _, hr := range healthReports {
		moduleCVEs[hr.Module] = hr.CVECount
	}

	// Build package→taint findings map
	pkgTaints := make(map[string][]taint.TaintFinding)
	for _, tf := range filteredTaint {
		pkgTaints[tf.Package] = append(pkgTaints[tf.Package], tf)
	}

	// Project-wide topology score is shared across all packages.
	topoScore := topoReport.Score
	integScore := integReport.Score

	for _, cr := range capReports {
		if excluded[cr.Package] {
			continue
		}
		pkg := g.Packages[cr.Package]
		if pkg == nil || pkg.Module == nil {
			continue
		}

		effectiveCaps := cr.Capabilities
		if exCaps := exceptions[cr.Package]; len(exCaps) > 0 {
			effectiveCaps = cr.Capabilities.Without(exCaps)
		}

		// Per-package diff score: sum of RiskDelta for this package name.
		pkgDiffScore := 0.0
		if *base != "" {
			for _, pd := range diffReport.NewPackages {
				if strings.HasPrefix(pd.Package, cr.Package+"@") || pd.Package == cr.Package {
					pkgDiffScore += pd.RiskDelta
				}
			}
			for _, pd := range diffReport.Escalations {
				if strings.HasPrefix(pd.Package, cr.Package+"@") || pd.Package == cr.Package {
					pkgDiffScore += pd.RiskDelta
				}
			}
		}

		finalScore := priority.ComputeFinal(
			effectiveCaps,
			nil,
			pkgTaints[cr.Package],
			pkgDiffScore,
			integScore,
			topoScore,
		)

		if capability.RiskValue(finalScore.Level) >= failLevel {
			sr.Passed = false
			sr.FailReason = fmt.Sprintf("package %s has %s risk (score: %.1f)", cr.Package, finalScore.Level, finalScore.Final)
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

	if sr.Passed && *online {
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
		writeTopologySection(os.Stdout, &topoReport)
		writeIntegritySection(os.Stdout, &integReport)
		if *base != "" {
			writeDiffSection(os.Stdout, &diffReport)
		}
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
		total := loadDur + capDur + engineDur + outDur
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "=== Timings ===")
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "graph load", fmtDur(loadDur))
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "capability detect", fmtDur(capDur))
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "engines (parallel)", fmtDur(engineDur))
		if *online {
			fmt.Fprintf(os.Stdout, "  %-23s  (%d modules, %d workers)\n",
				"health scoring", healthTiming.ModuleCount, healthTiming.Workers)
			fmt.Fprintf(os.Stdout, "  %-23s  %s  (%d calls)\n", "github API", fmtDur(healthTiming.GithubTime), healthTiming.GithubCalls)
			fmt.Fprintf(os.Stdout, "  %-23s  %s  (%d calls)\n", "osv API", fmtDur(healthTiming.OsvTime), healthTiming.OsvCalls)
		}
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "output formatting", fmtDur(outDur))
		fmt.Fprintln(os.Stdout, strings.Repeat("─", 40))
		fmt.Fprintf(os.Stdout, "%-25s  %s\n", "total", fmtDur(total))
	}

	if !sr.Passed {
		return 1
	}
	return 0
}

func writeTopologySection(w *os.File, r *topology.TopologyReport) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== Topology ===")
	fmt.Fprintf(w, "Direct deps: %d   Total: %d   MaxDepth: %d\n",
		r.DirectDeps, r.TotalDeps, r.MaxDepth)
	fmt.Fprintf(w, "DeepPackagePct: %.1f%%   MajorVersionSkew: %d   DuplicateVersions: %d   LockfileChurn(90d): %d\n",
		r.DeepPackagePct, r.MajorVersionSkew, r.DuplicateVersions, r.LockfileChurn)
	fmt.Fprintf(w, "%-22s  %6s  %5s\n", "Signal", "Value", "Score")
	fmt.Fprintln(w, strings.Repeat("─", 38))
	for _, s := range r.Signals {
		fmt.Fprintf(w, "%-22s  %6d  %5.1f\n", s.Name, s.Value, s.Score)
	}
	fmt.Fprintf(w, "%-22s  %6s  %5.1f\n", "TOTAL", "", r.Score)
}

func writeIntegritySection(w *os.File, r *integrity.IntegrityReport) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== Integrity ===")
	fmt.Fprintf(w, "Packages: %d   Coverage: %.1f%%   Score: %.1f\n",
		r.TotalPackages, r.Coverage, r.Score)
	if len(r.Violations) > 0 {
		fmt.Fprintf(w, "%-40s  %-20s  %5s\n", "Package", "Type", "Score")
		fmt.Fprintln(w, strings.Repeat("─", 70))
		for _, v := range r.Violations {
			fmt.Fprintf(w, "%-40s  %-20s  %5.1f\n", v.Package, v.Type, v.Score)
		}
	}
}

func writeDiffSection(w *os.File, r *versiondiff.DiffReport) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "=== Version Diff (base: %s) ===\n", r.Base)
	fmt.Fprintf(w, "New packages: %d   Escalations: %d   Score: %.1f\n",
		len(r.NewPackages), len(r.Escalations), r.Score)
	if len(r.NewPackages) > 0 {
		fmt.Fprintln(w, "\nNew packages:")
		fmt.Fprintf(w, "  %-45s  %-10s  %5s\n", "Package", "Change", "Delta")
		for _, pd := range r.NewPackages {
			fmt.Fprintf(w, "  %-45s  %-10s  %5.1f\n", pd.Package, pd.ChangeType, pd.RiskDelta)
		}
	}
	if len(r.Escalations) > 0 {
		fmt.Fprintln(w, "\nEscalations:")
		fmt.Fprintf(w, "  %-45s  %-10s  %5s\n", "Package", "Change", "Delta")
		for _, pd := range r.Escalations {
			fmt.Fprintf(w, "  %-45s  %-10s  %5.1f\n", pd.Package, pd.ChangeType, pd.RiskDelta)
		}
	}
}

func fmtDur(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
