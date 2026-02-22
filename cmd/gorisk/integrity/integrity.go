// Package integritycmd implements the `gorisk integrity` subcommand.
package integritycmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/engines/integrity"
)

// Run executes the integrity subcommand and returns an exit code.
func Run(args []string) int {
	fs := flag.NewFlagSet("integrity", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language: auto|go|node")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	r, err := integrity.Check(dir, *lang)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integrity:", err)
		return 2
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		// Exit 1 if any git_dep violations.
		for _, v := range r.Violations {
			if v.Type == "git_dep" || v.Type == "git_replace" {
				return 1
			}
		}
		return 0
	}

	// Text output.
	fmt.Fprintf(os.Stdout, "=== Integrity ===\n")
	fmt.Fprintf(os.Stdout, "Packages: %d   Coverage: %.1f%%   Score: %.1f\n",
		r.TotalPackages, r.Coverage, r.Score)

	if len(r.Violations) > 0 {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintf(os.Stdout, "%-40s  %-20s  %5s  %s\n", "Package", "Type", "Score", "Detail")
		fmt.Fprintln(os.Stdout, strings.Repeat("─", 90))
		for _, v := range r.Violations {
			detail := v.Detail
			if len(detail) > 40 {
				detail = detail[:37] + "..."
			}
			fmt.Fprintf(os.Stdout, "%-40s  %-20s  %5.1f  %s\n", v.Package, v.Type, v.Score, detail)
		}
	} else {
		fmt.Fprintln(os.Stdout, "No integrity violations found.")
	}

	// Exit 1 if any git_dep violations.
	for _, v := range r.Violations {
		if v.Type == "git_dep" || v.Type == "git_replace" {
			return 1
		}
	}
	return 0
}
