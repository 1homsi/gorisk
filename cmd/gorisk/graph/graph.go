package graph

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/transitive"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	minRisk := fs.String("min-risk", "low", "minimum risk level to show: low|medium|high")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	g, err := graph.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	risks := transitive.ComputeTransitiveRisk(g)

	minLevel := riskValue(*minRisk)
	var filtered []transitive.ModuleRisk
	for _, r := range risks {
		if riskValue(r.RiskLevel) >= minLevel {
			filtered = append(filtered, r)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].EffectiveScore > filtered[j].EffectiveScore
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if filtered == nil {
			filtered = []transitive.ModuleRisk{}
		}
		enc.Encode(filtered)
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

	fmt.Printf("%s%-60s  %6s  %6s  %6s  %5s  %-6s%s\n",
		bold, "MODULE", "DIRECT", "TRANS.", "EFFECT", "DEPTH", "RISK", reset)
	fmt.Println(strings.Repeat("─", 100))

	for _, r := range filtered {
		col := colorForRisk(r.RiskLevel)
		fmt.Printf("%-60s  %6d  %6d  %6d  %5d  %s%-6s%s\n",
			r.Module,
			r.DirectScore,
			r.TransitiveScore,
			r.EffectiveScore,
			r.Depth,
			col, r.RiskLevel, reset,
		)
	}

	if len(filtered) == 0 {
		fmt.Println("no modules matching filter")
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
