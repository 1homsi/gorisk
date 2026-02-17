package reachability

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/reachability"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("reachability", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	minRisk := fs.String("min-risk", "low", "minimum risk level to show: low|medium|high")
	fs.Parse(args)

	pattern := "./..."
	if fs.NArg() > 0 {
		pattern = fs.Arg(0)
	}

	reports, err := reachability.Analyze(pattern)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reachability analysis:", err)
		return 2
	}

	minLevel := riskValue(*minRisk)
	var filtered []reachability.ReachabilityReport
	for _, r := range reports {
		if riskValue(r.ReachableCaps.RiskLevel()) >= minLevel {
			filtered = append(filtered, r)
		}
	}

	if *jsonOut {
		type jsonEntry struct {
			Package   string   `json:"package"`
			Reachable bool     `json:"reachable"`
			Risk      string   `json:"risk"`
			Score     int      `json:"score"`
			Caps      []string `json:"capabilities"`
		}
		var out []jsonEntry
		for _, r := range filtered {
			out = append(out, jsonEntry{
				Package:   r.Package,
				Reachable: r.Reachable,
				Risk:      r.ReachableCaps.RiskLevel(),
				Score:     r.ReachableCaps.Score,
				Caps:      r.ReachableCaps.List(),
			})
		}
		if out == nil {
			out = []jsonEntry{}
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
		gray   = "\033[90m"
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

	for _, r := range filtered {
		risk := r.ReachableCaps.RiskLevel()
		col := colorForRisk(risk)
		reachLabel := gray + "unreachable" + reset
		if r.Reachable {
			reachLabel = col + "REACHABLE" + reset
		}
		fmt.Printf("%s%-60s%s  %s%-6s%s  %s\n",
			col, r.Package, reset,
			col, risk, reset,
			reachLabel,
		)
		fmt.Printf("  caps: %s\n", strings.Join(r.ReachableCaps.List(), ", "))
	}

	if len(filtered) == 0 {
		fmt.Println("no capabilities found matching filter")
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
