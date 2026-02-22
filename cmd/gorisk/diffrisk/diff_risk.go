// Package diffrisk implements the `gorisk diff-risk` subcommand.
package diffrisk

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/engines/versiondiff"
)

// Run executes the diff-risk subcommand and returns an exit code.
func Run(args []string) int {
	fs := flag.NewFlagSet("diff-risk", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language: auto|go|node")
	base := fs.String("base", "", "git ref or lockfile path to compare against (required)")
	fs.Parse(args)

	if *base == "" {
		fmt.Fprintln(os.Stderr, "diff-risk: --base is required")
		fmt.Fprintln(os.Stderr, "usage: gorisk diff-risk --base <ref|path> [--json] [--lang auto|go|node]")
		return 2
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	r, err := versiondiff.Compute(dir, *base, *lang)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diff-risk:", err)
		return 2
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return exitCode(r)
	}

	// Text output.
	fmt.Fprintf(os.Stdout, "=== Version Diff (base: %s) ===\n", r.Base)
	fmt.Fprintf(os.Stdout, "New packages: %d   Escalations: %d   BlastRadiusDelta: %d   Score: %.1f\n",
		len(r.NewPackages), len(r.Escalations), r.BlastRadiusDelta, r.Score)

	if len(r.NewPackages) > 0 {
		fmt.Fprintln(os.Stdout, "\nNew packages:")
		fmt.Fprintf(os.Stdout, "  %-45s  %-10s  %5s  %s\n", "Package", "Change", "Delta", "Capabilities")
		fmt.Fprintln(os.Stdout, "  "+strings.Repeat("─", 80))
		for _, pd := range r.NewPackages {
			caps := strings.Join(pd.NewCaps, ",")
			if caps == "" {
				caps = "—"
			}
			fmt.Fprintf(os.Stdout, "  %-45s  %-10s  %5.1f  %s\n", pd.Package, pd.ChangeType, pd.RiskDelta, caps)
		}
	}

	if len(r.Escalations) > 0 {
		fmt.Fprintln(os.Stdout, "\nEscalations:")
		fmt.Fprintf(os.Stdout, "  %-45s  %-10s  %5s  %s → %s\n", "Package", "Change", "Delta", "OldCaps", "NewCaps")
		fmt.Fprintln(os.Stdout, "  "+strings.Repeat("─", 80))
		for _, pd := range r.Escalations {
			oldC := strings.Join(pd.OldCaps, ",")
			newC := strings.Join(pd.NewCaps, ",")
			if oldC == "" {
				oldC = "—"
			}
			if newC == "" {
				newC = "—"
			}
			fmt.Fprintf(os.Stdout, "  %-45s  %-10s  %5.1f  %s → %s\n", pd.Package, pd.ChangeType, pd.RiskDelta, oldC, newC)
		}
	}

	if len(r.NewPackages) == 0 && len(r.Escalations) == 0 {
		fmt.Fprintln(os.Stdout, "No risk-relevant changes found.")
	}

	return exitCode(r)
}

// exitCode returns 1 if there are any HIGH escalations/new packages, 0 otherwise.
func exitCode(r versiondiff.DiffReport) int {
	for _, pd := range r.NewPackages {
		if pd.RiskDelta >= 15 {
			return 1
		}
	}
	for _, pd := range r.Escalations {
		if pd.RiskDelta >= 15 {
			return 1
		}
	}
	return 0
}
