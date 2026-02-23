package pr

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/prdiff"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("pr", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	base := fs.String("base", "origin/main", "base ref to diff against")
	head := fs.String("head", "HEAD", "head ref to diff")
	lang := fs.String("lang", "auto", "language: auto|go|node")
	comment := fs.Bool("comment", false, "post scan diff as a GitHub PR comment (requires GITHUB_TOKEN and GORISK_PR_URL)")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	features, err := analyzer.FeaturesFor(*lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "features:", err)
		return 2
	}
	report, err := features.PRDiff.Diff(*base, *head)
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

	if *comment {
		if code := postGitHubComment(report); code != 0 {
			return code
		}
	}

	if failed {
		fmt.Fprintln(os.Stderr, "✗ FAILED: new HIGH risk dependency introduced")
		return 1
	}
	return 0
}

// postGitHubComment posts the scan diff as a markdown comment on the GitHub PR
// identified by GORISK_PR_URL. Requires GITHUB_TOKEN to be set.
func postGitHubComment(report prdiff.PRDiffReport) int {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "warning: GITHUB_TOKEN not set — skipping GitHub PR comment")
		return 0
	}

	prURL := os.Getenv("GORISK_PR_URL")
	if prURL == "" {
		fmt.Fprintln(os.Stderr, "warning: GORISK_PR_URL not set — skipping GitHub PR comment")
		return 0
	}

	body := buildCommentBody(report)

	commentsURL := strings.TrimRight(prURL, "/") + "/comments"

	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal comment:", err)
		return 2
	}

	req, err := http.NewRequest("POST", commentsURL, bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, "build request:", err)
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "post comment:", err)
		return 2
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "github API returned %d when posting comment\n", resp.StatusCode)
		return 2
	}

	fmt.Fprintln(os.Stdout, "posted gorisk scan diff as GitHub PR comment")
	return 0
}

// buildCommentBody renders the PRDiffReport as a markdown table comment.
func buildCommentBody(report prdiff.PRDiffReport) string {
	var sb strings.Builder
	sb.WriteString("## gorisk scan diff\n\n")
	sb.WriteString("| Package | Before | After | New Caps |\n")
	sb.WriteString("|---------|--------|-------|----------|\n")

	for _, m := range report.Added {
		caps := strings.Join(m.Caps.List(), ", ")
		fmt.Fprintf(&sb, "| %s | — | %s | %s |\n", m.Module, m.Caps.RiskLevel(), caps)
	}
	for _, m := range report.Updated {
		// Derive "before" from old caps being lower; we only have old risk via CapEscalated flag.
		// Use the version strings as a proxy since old caps aren't stored separately.
		caps := strings.Join(m.Caps.List(), ", ")
		before := m.OldVersion
		after := m.NewVersion + " (" + m.Caps.RiskLevel() + ")"
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", m.Module, before, after, caps)
	}
	for _, mod := range report.Removed {
		fmt.Fprintf(&sb, "| %s | removed | — | — |\n", mod)
	}

	sb.WriteString("\n> Generated by gorisk pr\n")
	return sb.String()
}
