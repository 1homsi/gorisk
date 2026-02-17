package report

import (
	"encoding/json"
	"fmt"
	"io"
)

type CapDiffReport struct {
	Module     string
	OldVersion string
	NewVersion string
	Diffs      []PackageCapDiff
	Escalated  bool
}

type PackageCapDiff struct {
	Package   string
	Added     []string
	Removed   []string
	Escalated bool
}

func WriteCapDiff(w io.Writer, r CapDiffReport) {
	fmt.Fprintf(w, "%s%s=== Capability Diff ===%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s → %s  (%s)\n\n", r.OldVersion, r.NewVersion, r.Module)

	if len(r.Diffs) == 0 {
		fmt.Fprintf(w, "%sNo capability changes.%s\n", colorGreen, colorReset)
		return
	}

	for _, d := range r.Diffs {
		prefix := " "
		if d.Escalated {
			prefix = colorRed + "⚠" + colorReset
		}
		fmt.Fprintf(w, "%s %s%s%s\n", prefix, colorBold, d.Package, colorReset)
		for _, a := range d.Added {
			fmt.Fprintf(w, "    %s+ %s%s\n", colorRed, a, colorReset)
		}
		for _, rm := range d.Removed {
			fmt.Fprintf(w, "    %s- %s%s\n", colorGreen, rm, colorReset)
		}
	}

	if r.Escalated {
		fmt.Fprintf(w, "\n%s%s⚠ CAPABILITY ESCALATION DETECTED — review before upgrading%s\n",
			colorBold, colorRed, colorReset)
	}
}

func WriteCapDiffJSON(w io.Writer, r CapDiffReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
