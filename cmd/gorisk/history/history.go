package history

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
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
	case "trend":
		var trendArgs []string
		if len(rest) > 1 {
			trendArgs = rest[1:]
		}
		return runTrend(dir, *jsonOut, trendArgs...)
	case "", "diff":
		var diffArgs []string
		if len(rest) > 1 {
			diffArgs = rest[1:]
		}
		return runDiff(dir, *jsonOut, diffArgs...)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", sub)
		fmt.Fprintln(os.Stderr, "usage: gorisk history [record|diff|show|trend] [--json] [N [M]]")
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
		red   = "\033[31m"
		green = "\033[32m"
		gray  = "\033[90m"
	)

	fmt.Printf("%s%-4s  %-25s  %-12s  %6s  %4s  %6s  %5s  %-12s%s\n",
		bold, "#", "TIMESTAMP", "COMMIT", "MODULES", "HIGH", "MEDIUM", "LOW", "TREND", reset)
	fmt.Println(strings.Repeat("─", 90))

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

		trend := gray + "—" + reset
		if i > 0 {
			prevSnap := h.Snapshots[i-1]
			prevHigh := 0
			for _, m := range prevSnap.Modules {
				if m.RiskLevel == "HIGH" {
					prevHigh++
				}
			}
			delta := high - prevHigh
			switch {
			case delta > 0:
				trend = fmt.Sprintf("%s↑ +%dH%s", red, delta, reset)
			case delta < 0:
				trend = fmt.Sprintf("%s↓ %dH%s", green, delta, reset)
			default:
				trend = gray + "→" + reset
			}
		}

		fmt.Printf("%-4d  %-25s  %-12s  %6d  %4d  %6d  %5d  %s\n",
			i+1, snap.Timestamp, commit, len(snap.Modules), high, med, low, trend)
	}
	return 0
}

func runTrend(dir string, jsonOut bool, args ...string) int {
	h, err := history.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load history:", err)
		return 2
	}

	if len(h.Snapshots) == 0 {
		fmt.Println("no history recorded; run: gorisk history record")
		return 0
	}

	// Parse optional --module flag from args
	moduleFilter := ""
	for i, a := range args {
		if a == "--module" && i+1 < len(args) {
			moduleFilter = args[i+1]
		}
	}

	// Collect all module names across all snapshots
	allModules := make(map[string]bool)
	for _, snap := range h.Snapshots {
		for _, m := range snap.Modules {
			if moduleFilter == "" || strings.Contains(m.Module, moduleFilter) {
				allModules[m.Module] = true
			}
		}
	}

	// For each module, collect scores across snapshots (up to last 10)
	const maxSnapshots = 10
	snapshots := h.Snapshots
	if len(snapshots) > maxSnapshots {
		snapshots = snapshots[len(snapshots)-maxSnapshots:]
	}

	type trendRow struct {
		Module     string
		Scores     []int
		FirstScore int
		LastScore  int
	}

	var rows []trendRow
	for mod := range allModules {
		scores := make([]int, 0, len(snapshots))
		for _, snap := range snapshots {
			found := false
			for _, m := range snap.Modules {
				if m.Module == mod {
					scores = append(scores, m.EffectiveScore)
					found = true
					break
				}
			}
			if !found {
				scores = append(scores, 0)
			}
		}
		firstScore, lastScore := 0, 0
		if len(scores) > 0 {
			firstScore = scores[0]
			lastScore = scores[len(scores)-1]
		}
		rows = append(rows, trendRow{
			Module:     mod,
			Scores:     scores,
			FirstScore: firstScore,
			LastScore:  lastScore,
		})
	}

	// Sort rows by module name
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Module < rows[j].Module
	})

	if jsonOut {
		type jsonRow struct {
			Module     string `json:"module"`
			Scores     []int  `json:"scores"`
			FirstScore int    `json:"first_score"`
			LastScore  int    `json:"last_score"`
			Change     int    `json:"change"`
		}
		var out []jsonRow
		for _, r := range rows {
			out = append(out, jsonRow{
				Module:     r.Module,
				Scores:     r.Scores,
				FirstScore: r.FirstScore,
				LastScore:  r.LastScore,
				Change:     r.LastScore - r.FirstScore,
			})
		}
		if out == nil {
			out = []jsonRow{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return 0
	}

	const (
		bold  = "\033[1m"
		reset = "\033[0m"
		red   = "\033[31m"
		green = "\033[32m"
		gray  = "\033[90m"
	)

	fmt.Printf("%s%-50s  %-20s  %5s  %5s  %-10s%s\n",
		bold, "MODULE", fmt.Sprintf("TREND (last %d)", len(snapshots)), "FIRST", "LAST", "CHANGE", reset)
	fmt.Println(strings.Repeat("─", 100))

	for _, r := range rows {
		sparkline := buildSparkline(r.Scores)
		change := r.LastScore - r.FirstScore
		changeStr := fmt.Sprintf("%+d", change)
		dirStr := gray + "→" + reset
		if change > 0 {
			dirStr = red + "↑" + reset
		} else if change < 0 {
			dirStr = green + "↓" + reset
		}
		mod := r.Module
		if len(mod) > 50 {
			mod = mod[:47] + "..."
		}
		fmt.Printf("%-50s  %-20s  %5d  %5d  %s%s  %s\n",
			mod, sparkline, r.FirstScore, r.LastScore, changeStr, reset, dirStr)
	}
	return 0
}

// buildSparkline converts a slice of scores (0–100) into a unicode block sparkline.
func buildSparkline(scores []int) string {
	// 8 block characters from low to high
	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	var sb strings.Builder
	for _, s := range scores {
		if s < 0 {
			s = 0
		}
		if s > 100 {
			s = 100
		}
		// Map 0–100 to 0–7
		idx := s * (len(blocks) - 1) / 100
		sb.WriteRune(blocks[idx])
	}
	return sb.String()
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
