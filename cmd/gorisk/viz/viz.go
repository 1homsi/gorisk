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

// d3Node is the node format for D3-compatible node-link JSON output.
type d3Node struct {
	ID   string `json:"id"`
	Risk string `json:"risk"`
}

// d3Link is the link format for D3-compatible node-link JSON output.
type d3Link struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// d3Graph is the top-level D3-compatible node-link JSON structure.
type d3Graph struct {
	Nodes []d3Node `json:"nodes"`
	Links []d3Link `json:"links"`
}

func Run(args []string) int {
	fs := flag.NewFlagSet("viz", flag.ExitOnError)
	minRisk := fs.String("min-risk", "low", "minimum risk level to show: low|medium|high")
	lang := fs.String("lang", "auto", "language analyzer: auto|go|node")
	format := fs.String("format", "html", "output format: html|json|dot")
	fs.Parse(args)

	switch *format {
	case "html", "json", "dot":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q: must be html, json, or dot\n", *format)
		return 2
	}

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

	minLevel := capability.RiskValue(*minRisk)

	// build package-level nodes — skip stdlib (no module) and low-risk if filtered
	included := make(map[string]bool)
	var nodes []nodeData
	for pkgPath, pkg := range g.Packages {
		if pkg.Module == nil {
			continue // stdlib
		}
		caps := pkg.Capabilities
		score := caps.Score
		risk := caps.RiskLevel()
		if capability.RiskValue(risk) < minLevel {
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

	switch *format {
	case "json":
		return outputJSON(nodes, edges)
	case "dot":
		return outputDOT(nodes, edges)
	default:
		return outputHTML(nodes, edges, mainPath)
	}
}

func outputHTML(nodes []nodeData, edges []edgeData, mainPath string) int {
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

func outputJSON(nodes []nodeData, edges []edgeData) int {
	d3nodes := make([]d3Node, len(nodes))
	for i, n := range nodes {
		d3nodes[i] = d3Node{ID: n.ID, Risk: n.Risk}
	}

	d3links := make([]d3Link, len(edges))
	for i, e := range edges {
		d3links[i] = d3Link(e)
	}

	g := d3Graph{
		Nodes: d3nodes,
		Links: d3links,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return 2
	}
	return 0
}

func outputDOT(nodes []nodeData, edges []edgeData) int {
	// Build a risk lookup for edge labels
	riskOf := make(map[string]string, len(nodes))
	for _, n := range nodes {
		riskOf[n.ID] = n.Risk
	}

	fmt.Println("digraph {")
	for _, e := range edges {
		risk := riskOf[e.Source]
		fmt.Printf("  %q -> %q [label=%q]\n", e.Source, e.Target, risk)
	}
	fmt.Println("}")
	return 0
}

func shortLabel(pkgPath string) string {
	parts := strings.Split(pkgPath, "/")
	if len(parts) <= 2 {
		return pkgPath
	}
	return strings.Join(parts[len(parts)-2:], "/")
}
