package graph

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/health"
	"github.com/1homsi/gorisk/internal/priority"
	"github.com/1homsi/gorisk/internal/taint"
	"github.com/1homsi/gorisk/internal/transitive"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	minRisk := fs.String("min-risk", "low", "minimum risk level to show: low|medium|high")
	lang := fs.String("lang", "auto", "language analyzer: auto|go|node")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	a, err := analyzer.ForLang(*lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	g, err := a.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	// Compute health scores and taint findings for composite scoring
	seen := make(map[string]bool)
	var mods []health.ModuleRef
	for _, mod := range g.Modules {
		if mod.Main || seen[mod.Path] {
			continue
		}
		seen[mod.Path] = true
		mods = append(mods, health.ModuleRef{Path: mod.Path, Version: mod.Version})
	}
	healthReports, _ := health.ScoreAll(mods)
	taintFindings := taint.Analyze(g.Packages)

	// Build module→CVE count and module→taint findings maps
	moduleCVEs := make(map[string]int)
	for _, hr := range healthReports {
		moduleCVEs[hr.Module] = hr.CVECount
	}

	moduleTaints := make(map[string][]taint.TaintFinding)
	for _, tf := range taintFindings {
		moduleTaints[tf.Module] = append(moduleTaints[tf.Module], tf)
	}

	risks := transitive.ComputeTransitiveRisk(g)

	// Augment risks with composite scores
	type moduleRiskWithComposite struct {
		transitive.ModuleRisk
		CompositeScore float64
	}

	var risksWithComposite []moduleRiskWithComposite
	for _, r := range risks {
		// Get the maximum capability set for this module
		var maxCaps capability.CapabilitySet
		for _, pkg := range g.Packages {
			if pkg.Module != nil && pkg.Module.Path == r.Module {
				if pkg.Capabilities.Score > maxCaps.Score {
					maxCaps = pkg.Capabilities
				}
			}
		}

		composite := priority.Compute(
			maxCaps,
			nil, // reachability unknown
			moduleCVEs[r.Module],
			moduleTaints[r.Module],
		)

		risksWithComposite = append(risksWithComposite, moduleRiskWithComposite{
			ModuleRisk:     r,
			CompositeScore: composite.Composite,
		})
	}

	minLevel := capability.RiskValue(*minRisk)
	var filtered []moduleRiskWithComposite
	for _, r := range risksWithComposite {
		if capability.RiskValue(r.RiskLevel) >= minLevel {
			filtered = append(filtered, r)
		}
	}

	// Sort by composite score instead of effective score
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CompositeScore > filtered[j].CompositeScore
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		// Convert back to plain ModuleRisk for JSON output
		plainRisks := make([]transitive.ModuleRisk, 0, len(filtered))
		for _, r := range filtered {
			plainRisks = append(plainRisks, r.ModuleRisk)
		}
		enc.Encode(plainRisks)
		return 0
	}

	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		bold   = "\033[1m"
		reset  = "\033[0m"
	)

	colorForRisk := func(risk string) string {
		switch risk {
		case "HIGH":
			return red
		case "MEDIUM":
			return yellow
		default:
			return green
		}
	}

	fmt.Printf("%s%-55s  %6s  %6s  %6s  %8s  %5s  %-6s%s\n",
		bold, "MODULE", "DIRECT", "TRANS.", "EFFECT", "COMPOSIT", "DEPTH", "RISK", reset)
	fmt.Println(strings.Repeat("─", 110))

	for _, r := range filtered {
		col := colorForRisk(r.RiskLevel)
		fmt.Printf("%-55s  %6d  %6d  %6d  %8.1f  %5d  %s%-6s%s\n",
			r.Module,
			r.DirectScore,
			r.TransitiveScore,
			r.EffectiveScore,
			r.CompositeScore,
			r.Depth,
			col, r.RiskLevel, reset,
		)
	}

	if len(filtered) == 0 {
		fmt.Println("no modules matching filter")
	}

	return 0
}
