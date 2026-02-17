package sbom

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/health"
	"github.com/1homsi/gorisk/internal/report"
	"github.com/1homsi/gorisk/internal/sbom"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	format := fs.String("format", "cyclonedx", "output format: cyclonedx")
	fs.Parse(args)

	if *format != "cyclonedx" {
		fmt.Fprintf(os.Stderr, "unsupported format %q, only cyclonedx is supported\n", *format)
		return 2
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	g, err := graph.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	var capReports []report.CapabilityReport
	for _, pkg := range g.Packages {
		modPath := ""
		if pkg.Module != nil {
			modPath = pkg.Module.Path
		}
		capReports = append(capReports, report.CapabilityReport{
			Package:      pkg.ImportPath,
			Module:       modPath,
			Capabilities: pkg.Capabilities,
			RiskLevel:    pkg.Capabilities.RiskLevel(),
		})
	}

	var healthReports []report.HealthReport
	seen := make(map[string]bool)
	for _, mod := range g.Modules {
		if mod.Main || seen[mod.Path] {
			continue
		}
		seen[mod.Path] = true
		healthReports = append(healthReports, health.Score(mod.Path, mod.Version))
	}

	bom := sbom.Generate(g, capReports, healthReports)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bom); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return 2
	}
	return 0
}
