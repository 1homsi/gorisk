package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/1homsi/gorisk/internal/taint"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
	colorCyan   = "\033[36m"
)

func riskColor(level string) string {
	switch level {
	case "HIGH":
		return colorRed
	case "MEDIUM":
		return colorYellow
	default:
		return colorGreen
	}
}

func WriteCapabilities(w io.Writer, reports []CapabilityReport) {
	fmt.Fprintf(w, "%s%s=== Capability Report ===%s\n\n", colorBold, colorCyan, colorReset)

	if len(reports) == 0 {
		fmt.Fprintln(w, "no packages found")
		return
	}

	const (
		maxPkg  = 50
		maxMod  = 35
		maxCaps = 35
	)

	pkgW, modW := len("PACKAGE"), len("MODULE")
	for _, r := range reports {
		if l := len(r.Package); l > pkgW {
			pkgW = l
		}
		if l := len(r.Module); l > modW {
			modW = l
		}
	}
	if pkgW > maxPkg {
		pkgW = maxPkg
	}
	if modW > maxMod {
		modW = maxMod
	}

	sep := strings.Repeat("─", pkgW+modW+maxCaps+17)
	fmt.Fprintf(w, "%s%-*s  %-*s  %-*s  %5s  %-6s%s\n",
		colorBold, pkgW, "PACKAGE", modW, "MODULE", maxCaps, "CAPABILITIES", "SCORE", "RISK", colorReset)
	fmt.Fprintln(w, sep)

	for _, r := range reports {
		color := riskColor(r.RiskLevel)

		pkg := r.Package
		if len(pkg) > pkgW {
			pkg = pkg[:pkgW-3] + "..."
		}
		mod := r.Module
		if len(mod) > modW {
			mod = mod[:modW-3] + "..."
		}
		caps := r.Capabilities.String()
		if len(caps) > maxCaps {
			caps = caps[:maxCaps-3] + "..."
		}

		fmt.Fprintf(w, "%-*s  %-*s  %-*s  %5d  %s%-6s%s\n",
			pkgW, pkg,
			modW, mod,
			maxCaps, caps,
			r.Capabilities.Score,
			color, r.RiskLevel, colorReset)
	}
}

func WriteHealth(w io.Writer, reports []HealthReport) {
	fmt.Fprintf(w, "%s%s=== Health Report ===%s\n\n", colorBold, colorCyan, colorReset)

	if len(reports) == 0 {
		return
	}

	const maxMod = 50

	modW := len("MODULE")
	for _, r := range reports {
		if l := len(r.Module); l > modW {
			modW = l
		}
	}
	if modW > maxMod {
		modW = maxMod
	}

	sep := strings.Repeat("─", modW+34)
	fmt.Fprintf(w, "%s%-*s  %-12s  %5s  %4s  %-8s%s\n",
		colorBold, modW, "MODULE", "VERSION", "SCORE", "CVEs", "STATUS", colorReset)
	fmt.Fprintln(w, sep)

	for _, r := range reports {
		level := "LOW"
		if r.Score < 40 {
			level = "HIGH"
		} else if r.Score < 70 {
			level = "MEDIUM"
		}
		color := riskColor(level)

		mod := r.Module
		if len(mod) > modW {
			mod = mod[:modW-3] + "..."
		}

		status := "OK"
		if r.Archived {
			status = "ARCHIVED"
		}

		fmt.Fprintf(w, "%-*s  %-12s  %5d  %4d  %s%-8s%s\n",
			modW, mod,
			r.Version,
			r.Score,
			r.CVECount,
			color, status, colorReset)
	}

	// CVE details table — only printed when at least one vuln exists
	var vulnRows []struct{ module, id string }
	for _, r := range reports {
		for _, id := range r.CVEs {
			vulnRows = append(vulnRows, struct{ module, id string }{r.Module, id})
		}
	}
	if len(vulnRows) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s%s=== Vulnerabilities ===%s\n\n", colorBold, colorRed, colorReset)

	cveModW := len("MODULE")
	for _, row := range vulnRows {
		if l := len(row.module); l > cveModW {
			cveModW = l
		}
	}
	if cveModW > maxMod {
		cveModW = maxMod
	}

	cveSep := strings.Repeat("─", cveModW+22)
	fmt.Fprintf(w, "%s%-*s  %-20s%s\n", colorBold, cveModW, "MODULE", "VULNERABILITY ID", colorReset)
	fmt.Fprintln(w, cveSep)
	for _, row := range vulnRows {
		mod := row.module
		if len(mod) > cveModW {
			mod = mod[:cveModW-3] + "..."
		}
		fmt.Fprintf(w, "%-*s  %s%s%s\n", cveModW, mod, colorRed, row.id, colorReset)
	}
}

func WriteUpgrade(w io.Writer, r UpgradeReport) {
	fmt.Fprintf(w, "%s%s=== Upgrade Report ===%s\n\n", colorBold, colorCyan, colorReset)
	color := riskColor(r.Risk)
	fmt.Fprintf(w, "Module:  %s\n", r.Module)
	fmt.Fprintf(w, "Version: %s → %s\n", r.OldVer, r.NewVer)
	fmt.Fprintf(w, "Risk:    %s%s%s\n\n", color, r.Risk, colorReset)

	if len(r.Breaking) > 0 {
		fmt.Fprintf(w, "%sBreaking Changes:%s\n", colorBold, colorReset)
		for _, b := range r.Breaking {
			fmt.Fprintf(w, "  %s[%s]%s %s\n", colorRed, b.Kind, colorReset, b.Symbol)
			if b.OldSig != "" {
				fmt.Fprintf(w, "    old: %s\n", b.OldSig)
			}
			if b.NewSig != "" {
				fmt.Fprintf(w, "    new: %s\n", b.NewSig)
			}
			for _, u := range b.UsedIn {
				fmt.Fprintf(w, "    used in: %s\n", u)
			}
		}
	}

	if len(r.NewDeps) > 0 {
		fmt.Fprintf(w, "\n%sNew Transitive Dependencies:%s\n", colorBold, colorReset)
		for _, d := range r.NewDeps {
			fmt.Fprintf(w, "  + %s\n", d)
		}
	}
}

func WriteImpact(w io.Writer, r ImpactReport) {
	fmt.Fprintf(w, "%s%s=== Blast Radius Report ===%s\n\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "Module:            %s\n", r.Module)
	if r.Version != "" {
		fmt.Fprintf(w, "Version:           %s\n", r.Version)
	}
	fmt.Fprintf(w, "Affected Packages: %d\n", len(r.AffectedPackages))
	fmt.Fprintf(w, "Affected Binaries: %d\n", len(r.AffectedMains))
	fmt.Fprintf(w, "LOC Touched:       %d\n", r.LOCTouched)
	fmt.Fprintf(w, "Max Graph Depth:   %d\n", r.Depth)

	if len(r.AffectedPackages) > 0 {
		fmt.Fprintf(w, "\n%sAffected Packages:%s\n", colorBold, colorReset)
		for _, p := range r.AffectedPackages {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}

	if len(r.AffectedMains) > 0 {
		fmt.Fprintf(w, "\n%sAffected Binaries:%s\n", colorBold, colorReset)
		for _, m := range r.AffectedMains {
			fmt.Fprintf(w, "  %s%s%s\n", colorRed, m, colorReset)
		}
	}
}

// WriteTaintFindings prints the taint flow findings section.
func WriteTaintFindings(w io.Writer, findings []taint.TaintFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(w, "%s%s=== Taint Flows ===%s\n\n", colorBold, colorCyan, colorReset)

	modW := len("MODULE")
	for _, f := range findings {
		if l := len(f.Module); l > modW {
			modW = l
		}
	}
	const maxMod = 40
	if modW > maxMod {
		modW = maxMod
	}

	for _, f := range findings {
		color := riskColor(f.Risk)
		mod := f.Module
		if len(mod) > modW {
			mod = mod[:modW-3] + "..."
		}
		flow := f.Source + " → " + f.Sink
		fmt.Fprintf(w, "  %s%-6s%s  %-*s  %-18s  %s\n",
			color, f.Risk, colorReset,
			modW, mod,
			flow,
			f.Note)
	}
	fmt.Fprintln(w)
}

func WriteScan(w io.Writer, r ScanReport) {
	WriteCapabilities(w, r.Capabilities)
	fmt.Fprintln(w)
	WriteHealth(w, r.Health)
	fmt.Fprintln(w)
	WriteTaintFindings(w, r.TaintFindings)

	if r.Passed {
		fmt.Fprintf(w, "%s%s✓ PASSED%s\n", colorBold, colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "%s%s✗ FAILED%s: %s\n", colorBold, colorRed, colorReset, r.FailReason)
	}
}
