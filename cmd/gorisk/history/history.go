package history

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/history"
	"github.com/1homsi/gorisk/internal/transitive"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language analyzer: auto|go|node")
	fs.Parse(args)

	rest := fs.Args()
	sub := ""
	if len(rest) > 0 {
		sub = rest[0]
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	switch sub {
	case "record":
		return runRecord(dir, *lang)
	case "show":
		return runShow(dir, *jsonOut)
	case "", "diff":
		var diffArgs []string
		if len(rest) > 1 {
			diffArgs = rest[1:]
		}
		return runDiff(dir, *jsonOut, diffArgs...)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", sub)
		fmt.Fprintln(os.Stderr, "usage: gorisk history [record|diff|show] [--json] [N [M]]")
		return 2
	}
}

func runRecord(dir, lang string) int {
	a, err := analyzer.ForLang(lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load analyzer:", err)
		return 2
	}
	g, err := a.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	risks := transitive.ComputeTransitiveRisk(g)

	capsByModule := make(map[string][]string)
	versionByModule := make(map[string]string)
	for _, mod := range g.Modules {
		if !mod.Main {
			versionByModule[mod.Path] = mod.Version
		}
	}
	for _, pkg := range g.Packages {
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}
		for _, c := range pkg.Capabilities.List() {
			if !contains(capsByModule[pkg.Module.Path], c) {
				capsByModule[pkg.Module.Path] = append(capsByModule[pkg.Module.Path], c)
			}
		}
	}

	var modules []history.ModuleSnapshot
	for _, r := range risks {
		modules = append(modules, history.ModuleSnapshot{
			Module:         r.Module,
			Version:        versionByModule[r.Module],
			RiskLevel:      r.RiskLevel,
			EffectiveScore: r.EffectiveScore,
			Capabilities:   capsByModule[r.Module],
		})
	}

	snap := history.Snapshot{
		Commit:  currentCommit(),
		Modules: modules,
	}

	h, err := history.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load history:", err)
		return 2
	}
	h.Record(snap)
	if err := h.Save(dir); err != nil {
		fmt.Fprintln(os.Stderr, "save history:", err)
		return 2
	}

	last := h.Snapshots[len(h.Snapshots)-1]
	fmt.Printf("recorded snapshot at %s  modules=%d  commit=%s\n",
		last.Timestamp, len(modules), snap.Commit)
	return 0
}

func runDiff(dir string, jsonOut bool, indices ...string) int {
	h, err := history.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load history:", err)
		return 2
	}
	n := len(h.Snapshots)
	if n < 2 {
		fmt.Fprintln(os.Stderr, "need at least 2 snapshots; run: gorisk history record")
		return 1
	}

	parseIdx := func(s string) (int, bool) {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 || v > n {
			fmt.Fprintf(os.Stderr, "snapshot index %q out of range 1..%d\n", s, n)
			return 0, false
		}
		return v - 1, true
	}

	oldIdx, curIdx := n-2, n-1
	switch len(indices) {
	case 1:
		i, ok := parseIdx(indices[0])
		if !ok {
			return 2
		}
		oldIdx = i
	case 2:
		i, ok := parseIdx(indices[0])
		if !ok {
			return 2
		}
		j, ok := parseIdx(indices[1])
		if !ok {
			return 2
		}
		oldIdx, curIdx = i, j
	}

	old := h.Snapshots[oldIdx]
	cur := h.Snapshots[curIdx]
	diffs := history.Diff(old, cur)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(diffs)
		return 0
	}

	printDiff(old, cur, diffs)
	return 0
}

func runShow(dir string, jsonOut bool) int {
	h, err := history.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load history:", err)
		return 2
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(h.Snapshots)
		return 0
	}

	if len(h.Snapshots) == 0 {
		fmt.Println("no history recorded; run: gorisk history record")
		return 0
	}

	const (
		bold  = "\033[1m"
		reset = "\033[0m"
	)
	fmt.Printf("%s%-4s  %-25s  %-12s  %6s  %4s  %6s  %5s%s\n",
		bold, "#", "TIMESTAMP", "COMMIT", "MODULES", "HIGH", "MEDIUM", "LOW", reset)
	fmt.Println(strings.Repeat("─", 75))

	for i, snap := range h.Snapshots {
		high, med, low := 0, 0, 0
		for _, m := range snap.Modules {
			switch m.RiskLevel {
			case "HIGH":
				high++
			case "MEDIUM":
				med++
			default:
				low++
			}
		}
		commit := snap.Commit
		if commit == "" {
			commit = "—"
		}
		fmt.Printf("%-4d  %-25s  %-12s  %6d  %4d  %6d  %5d\n",
			i+1, snap.Timestamp, commit, len(snap.Modules), high, med, low)
	}
	return 0
}

func printDiff(old, cur history.Snapshot, diffs []history.ModuleDiff) {
	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		bold   = "\033[1m"
		reset  = "\033[0m"
	)

	fmt.Printf("%sdrift  %s → %s%s\n\n", bold, old.Timestamp, cur.Timestamp, reset)

	added, removed, escalated, improved := 0, 0, 0, 0
	for _, d := range diffs {
		switch d.Change {
		case "added":
			added++
			col := riskColor(d.New.RiskLevel, red, yellow, green)
			fmt.Printf("  %s+  %-60s  %s%s\n", col, d.Module, d.New.RiskLevel, reset)
		case "removed":
			removed++
			fmt.Printf("  %s-  %-60s%s\n", green, d.Module, reset)
		case "escalated":
			escalated++
			col := riskColor(d.New.RiskLevel, red, yellow, green)
			fmt.Printf("  %s↑  %-60s  %s → %s%s\n", col, d.Module, d.Old.RiskLevel, d.New.RiskLevel, reset)
		case "improved":
			improved++
			fmt.Printf("  %s↓  %-60s  %s → %s%s\n", green, d.Module, d.Old.RiskLevel, d.New.RiskLevel, reset)
		}
	}

	fmt.Printf("\n  added=%d  removed=%d  escalated=%d  improved=%d\n",
		added, removed, escalated, improved)
}

func riskColor(risk, red, yellow, green string) string {
	switch risk {
	case "HIGH":
		return red
	case "MEDIUM":
		return yellow
	default:
		return green
	}
}

func currentCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
