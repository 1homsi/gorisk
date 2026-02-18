package capabilities

import (
	"flag"
	"fmt"
	"os"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("capabilities", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
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

	var reports []report.CapabilityReport
	for _, pkg := range g.Packages {
		riskLevel := pkg.Capabilities.RiskLevel()
		if !meetsMinRisk(riskLevel, *minRisk) {
			continue
		}
		modPath := ""
		if pkg.Module != nil {
			modPath = pkg.Module.Path
		}
		reports = append(reports, report.CapabilityReport{
			Package:      pkg.ImportPath,
			Module:       modPath,
			Capabilities: pkg.Capabilities,
			RiskLevel:    riskLevel,
		})
	}

	if *jsonOut {
		if err := report.WriteCapabilitiesJSON(os.Stdout, reports); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			return 2
		}
	} else {
		report.WriteCapabilities(os.Stdout, reports)
	}

	for _, r := range reports {
		if r.RiskLevel == "HIGH" {
			return 1
		}
	}
	return 0
}

func meetsMinRisk(level, min string) bool {
	return capability.RiskValue(level) >= capability.RiskValue(min)
}
