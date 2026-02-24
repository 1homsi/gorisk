package graph

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/astpipeline"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/engines/integrity"
	"github.com/1homsi/gorisk/internal/engines/topology"
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

	taintFindings := taint.Analyze(g.Packages)
	resolvedLang := analyzer.ResolveLang(*lang, dir)
	astResult := astpipeline.Analyze(dir, resolvedLang, g)
	if astResult.UsedInterproc && len(astResult.Bundle.TaintFindings) > 0 {
		taintFindings = astResult.Bundle.TaintFindings
	}

	topoReport, _ := topology.Compute(dir, *lang)
	integReport, _ := integrity.Check(dir, *lang)

	moduleTaints := make(map[string][]taint.TaintFinding) // module -> taint findings
	for _, tf := range taintFindings {
		mod := tf.Module
		if pkg := g.Packages[tf.Package]; pkg != nil && pkg.Module != nil {
			mod = pkg.Module.Path
		}
		moduleTaints[mod] = append(moduleTaints[mod], tf)
	}

	// Aggregate package-level ReachabilityHints to module-level before scoring.
	// ReachabilityHints is keyed by package path; r.Module is a module path —
	// these are different key spaces. A module is "reachable" if any of its
	// packages are reachable; "unreachable" if some were analysed but none
	// reachable; nil (unknown) if no packages from that module appear in hints.
	type modReachState struct{ seen, reachable bool }
	modReach := make(map[string]modReachState)
	if astResult.UsedInterproc {
		for pkg, pkgReach := range astResult.Bundle.ReachabilityHints {
			if p := g.Packages[pkg]; p != nil && p.Module != nil {
				s := modReach[p.Module.Path]
				s.seen = true
				if pkgReach {
					s.reachable = true
				}
				modReach[p.Module.Path] = s
			}
		}
	}

	risks := transitive.ComputeTransitiveRisk(g)

	// Augment risks with composite scores
	type moduleRiskWithComposite struct {
		transitive.ModuleRisk
		Final priority.FinalScore
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

		var reachable *bool
		if s, ok := modReach[r.Module]; ok {
			v := s.reachable
			reachable = &v
		}
		final := priority.ComputeFinal(
			maxCaps,
			reachable,
			moduleTaints[r.Module],
			0,
			integReport.Score,
			topoReport.Score,
		)

		risksWithComposite = append(risksWithComposite, moduleRiskWithComposite{
			ModuleRisk: r,
			Final:      final,
		})
	}

	minLevel := capability.RiskValue(*minRisk)
	var filtered []moduleRiskWithComposite
	for _, r := range risksWithComposite {
		if capability.RiskValue(r.Final.Level) >= minLevel {
			filtered = append(filtered, r)
		}
	}

	// Sort by composite score instead of effective score
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Final.Final > filtered[j].Final.Final
	})

	if *jsonOut {
		type jsonModule struct {
			Module          string  `json:"module"`
			DirectScore     int     `json:"direct_score"`
			TransitiveScore int     `json:"transitive_score"`
			EffectiveScore  int     `json:"effective_score"`
			RiskLevel       string  `json:"risk_level"`
			Depth           int     `json:"depth"`
			FinalScore      float64 `json:"final_score"`
			FinalLevel      string  `json:"final_level"`
			SemanticScore   float64 `json:"semantic_score"`
		}
		out := make([]jsonModule, 0, len(filtered))
		for _, r := range filtered {
			out = append(out, jsonModule{
				Module:          r.Module,
				DirectScore:     r.DirectScore,
				TransitiveScore: r.TransitiveScore,
				EffectiveScore:  r.EffectiveScore,
				RiskLevel:       r.RiskLevel,
				Depth:           r.Depth,
				FinalScore:      r.Final.Final,
				FinalLevel:      r.Final.Level,
				SemanticScore:   r.Final.Semantic,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
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
		col := colorForRisk(r.Final.Level)
		fmt.Printf("%-55s  %6d  %6d  %6d  %8.1f  %5d  %s%-6s%s\n",
			r.Module,
			r.DirectScore,
			r.TransitiveScore,
			r.EffectiveScore,
			r.Final.Final,
			r.Depth,
			col, r.Final.Level, reset,
		)
	}

	if len(filtered) == 0 {
		fmt.Println("no modules matching filter")
	}

	return 0
}
