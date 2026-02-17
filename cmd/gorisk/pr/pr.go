package pr

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/prdiff"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("pr", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	base := fs.String("base", "origin/main", "base ref to diff against")
	head := fs.String("head", "HEAD", "head ref to diff")
	fs.Parse(args)

	report, err := prdiff.DiffGoMod(*base, *head)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pr diff:", err)
		return 2
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return 0
	}

	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
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

	failed := false

	if len(report.Added) > 0 {
		fmt.Println("Added dependencies:")
		for _, m := range report.Added {
			risk := m.Caps.RiskLevel()
			col := colorForRisk(risk)
			fmt.Printf("  %s+ %s %s%s  %s%-6s%s  caps: %s\n",
				col, m.Module, m.NewVersion, reset,
				col, risk, reset,
				strings.Join(m.Caps.List(), ", "),
			)
			if risk == "HIGH" {
				failed = true
			}
		}
	}

	if len(report.Updated) > 0 {
		fmt.Println("Updated dependencies:")
		for _, m := range report.Updated {
			risk := m.Caps.RiskLevel()
			col := colorForRisk(risk)
			escalated := ""
			if m.CapEscalated {
				escalated = red + " ▲ capability escalation" + reset
			}
			fmt.Printf("  %s~ %s %s → %s%s  %s%-6s%s%s  caps: %s\n",
				col, m.Module, m.OldVersion, m.NewVersion, reset,
				col, risk, reset,
				escalated,
				strings.Join(m.Caps.List(), ", "),
			)
		}
	}

	if len(report.Removed) > 0 {
		fmt.Println("Removed dependencies:")
		for _, m := range report.Removed {
			fmt.Printf("  - %s\n", m)
		}
	}

	if len(report.Added) == 0 && len(report.Updated) == 0 && len(report.Removed) == 0 {
		fmt.Println("no dependency changes detected")
	}

	if failed {
		fmt.Fprintln(os.Stderr, "✗ FAILED: new HIGH risk dependency introduced")
		return 1
	}
	return 0
}
