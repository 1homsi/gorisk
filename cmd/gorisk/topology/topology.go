// Package topologycmd implements the `gorisk topology` subcommand.
package topologycmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/engines/topology"
)

// Run executes the topology subcommand and returns an exit code.
func Run(args []string) int {
	fs := flag.NewFlagSet("topology", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language: auto|go|node")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	r, err := topology.Compute(dir, *lang)
	if err != nil {
		fmt.Fprintln(os.Stderr, "topology:", err)
		return 2
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}

	// Text output.
	fmt.Fprintf(os.Stdout, "=== Topology ===\n")
	fmt.Fprintf(os.Stdout, "Direct deps: %d   Total: %d   MaxDepth: %d\n",
		r.DirectDeps, r.TotalDeps, r.MaxDepth)
	fmt.Fprintf(os.Stdout, "DeepPackagePct: %.1f%%   MajorVersionSkew: %d   DuplicateVersions: %d   LockfileChurn(90d): %d\n",
		r.DeepPackagePct, r.MajorVersionSkew, r.DuplicateVersions, r.LockfileChurn)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%-22s  %6s  %5s\n", "Signal", "Value", "Score")
	fmt.Fprintln(os.Stdout, strings.Repeat("─", 38))
	for _, s := range r.Signals {
		fmt.Fprintf(os.Stdout, "%-22s  %6d  %5.1f\n", s.Name, s.Value, s.Score)
	}
	fmt.Fprintln(os.Stdout, strings.Repeat("─", 38))
	fmt.Fprintf(os.Stdout, "%-22s  %6s  %5.1f\n", "TOTAL", "", r.Score)

	return 0
}
