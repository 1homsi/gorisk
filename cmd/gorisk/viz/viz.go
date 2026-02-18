package viz

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/capability"
)

//go:embed template.html
var htmlTemplate string

//go:embed template.css
var cssTemplate string

//go:embed template.js
var jsTemplate string

type nodeData struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Module       string   `json:"module"`
	Risk         string   `json:"risk"`
	Score        int      `json:"score"`
	Capabilities []string `json:"capabilities,omitempty"`
	Files        int      `json:"files"`
	UsedBy       int      `json:"usedBy"`
	Uses         int      `json:"uses"`
	IsMain       bool     `json:"main"`
}

type edgeData struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type graphData struct {
	Nodes []nodeData `json:"nodes"`
	Edges []edgeData `json:"edges"`
	Main  string     `json:"main"`
}

func Run(args []string) int {
	fs := flag.NewFlagSet("viz", flag.ExitOnError)
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

	minLevel := riskValue(*minRisk)

	// build package-level nodes — skip stdlib (no module) and low-risk if filtered
	included := make(map[string]bool)
	var nodes []nodeData
	for pkgPath, pkg := range g.Packages {
		if pkg.Module == nil {
			continue // stdlib
		}
		caps := pkg.Capabilities
		score := caps.Score
		risk := riskLevel(caps)
		if riskValue(risk) < minLevel {
			continue
		}
		included[pkgPath] = true
		nodes = append(nodes, nodeData{
			ID:           pkgPath,
			Label:        shortLabel(pkgPath),
			Module:       pkg.Module.Path,
			Risk:         risk,
			Score:        score,
			Capabilities: caps.List(),
			Files:        len(pkg.GoFiles),
			IsMain:       pkg.Module.Main,
		})
	}

	// compute UsedBy / Uses counts from edges
	usedBy := make(map[string]int)
	uses := make(map[string]int)
	for src, targets := range g.Edges {
		if !included[src] {
			continue
		}
		for _, tgt := range targets {
			if !included[tgt] {
				continue
			}
			usedBy[tgt]++
			uses[src]++
		}
	}
	for i := range nodes {
		nodes[i].UsedBy = usedBy[nodes[i].ID]
		nodes[i].Uses = uses[nodes[i].ID]
	}

	// package-level edges — only between included packages, deduplicated
	edgeSeen := make(map[string]bool)
	var edges []edgeData
	for src, targets := range g.Edges {
		if !included[src] {
			continue
		}
		for _, tgt := range targets {
			if !included[tgt] || tgt == src {
				continue
			}
			key := src + "→" + tgt
			if !edgeSeen[key] {
				edgeSeen[key] = true
				edges = append(edges, edgeData{Source: src, Target: tgt})
			}
		}
	}

	if nodes == nil {
		nodes = []nodeData{}
	}
	if edges == nil {
		edges = []edgeData{}
	}

	mainPath := ""
	if g.Main != nil {
		mainPath = g.Main.Path
	}

	dataJSON, err := json.Marshal(graphData{Nodes: nodes, Edges: edges, Main: mainPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		return 2
	}

	out := strings.Replace(htmlTemplate, "__STYLE__", cssTemplate, 1)
	out = strings.Replace(out, "__SCRIPT__", jsTemplate, 1)
	out = strings.Replace(out, "__DATA__", string(dataJSON), 1)
	fmt.Print(out)
	return 0
}

func riskLevel(caps capability.CapabilitySet) string {
	switch {
	case caps.Score >= 30:
		return "HIGH"
	case caps.Score >= 10:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func shortLabel(pkgPath string) string {
	parts := strings.Split(pkgPath, "/")
	if len(parts) <= 2 {
		return pkgPath
	}
	return strings.Join(parts[len(parts)-2:], "/")
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
