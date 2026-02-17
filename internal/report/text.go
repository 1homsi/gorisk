package report

import (
	"fmt"
	"io"
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
	for _, r := range reports {
		color := riskColor(r.RiskLevel)
		fmt.Fprintf(w, "%s%-60s%s %s[%s]%s\n",
			colorBold, r.Package, colorReset,
			color, r.RiskLevel, colorReset,
		)
		if r.Capabilities.Caps != 0 {
			fmt.Fprintf(w, "  caps: %s\n", r.Capabilities.String())
			fmt.Fprintf(w, "  score: %d\n", r.Capabilities.Score)
		}
	}
}

func WriteHealth(w io.Writer, reports []HealthReport) {
	fmt.Fprintf(w, "%s%s=== Health Report ===%s\n\n", colorBold, colorCyan, colorReset)
	for _, r := range reports {
		level := "LOW"
		if r.Score < 40 {
			level = "HIGH"
		} else if r.Score < 70 {
			level = "MEDIUM"
		}
		color := riskColor(level)
		fmt.Fprintf(w, "%s%-50s%s score=%s%d%s",
			colorBold, r.Module, colorReset,
			color, r.Score, colorReset,
		)
		if r.Archived {
			fmt.Fprintf(w, " %s[ARCHIVED]%s", colorRed, colorReset)
		}
		if r.CVECount > 0 {
			fmt.Fprintf(w, " CVEs=%s%d%s", colorRed, r.CVECount, colorReset)
		}
		fmt.Fprintln(w)
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

func WriteScan(w io.Writer, r ScanReport) {
	WriteCapabilities(w, r.Capabilities)
	fmt.Fprintln(w)
	WriteHealth(w, r.Health)
	fmt.Fprintln(w)

	if r.Passed {
		fmt.Fprintf(w, "%s%s✓ PASSED%s\n", colorBold, colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "%s%s✗ FAILED%s: %s\n", colorBold, colorRed, colorReset, r.FailReason)
	}
}
