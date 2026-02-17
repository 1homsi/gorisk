package diff

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/report"
	"github.com/1homsi/gorisk/internal/upgrade"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: gorisk diff <module@old> <module@new>")
		return 2
	}

	modulePath, oldVer, ok := splitAt(fs.Arg(0))
	if !ok {
		fmt.Fprintln(os.Stderr, "specify version: module@version")
		return 2
	}
	_, newVer, ok := splitAt(fs.Arg(1))
	if !ok {
		fmt.Fprintln(os.Stderr, "specify version: module@version")
		return 2
	}

	diffs, err := upgrade.DiffCapabilities(modulePath, oldVer, newVer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diff:", err)
		return 2
	}

	r := report.CapDiffReport{
		Module:     modulePath,
		OldVersion: oldVer,
		NewVersion: newVer,
	}
	for _, d := range diffs {
		r.Diffs = append(r.Diffs, report.PackageCapDiff{
			Package:   d.Package,
			Added:     d.Added.List(),
			Removed:   d.Removed.List(),
			Escalated: d.Escalated,
		})
		if d.Escalated {
			r.Escalated = true
		}
	}

	if *jsonOut {
		if err := report.WriteCapDiffJSON(os.Stdout, r); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			return 2
		}
	} else {
		report.WriteCapDiff(os.Stdout, r)
	}

	if r.Escalated {
		return 1
	}
	return 0
}

func splitAt(s string) (left, right string, ok bool) {
	at := strings.LastIndex(s, "@")
	if at == -1 {
		return "", "", false
	}
	return s[:at], s[at+1:], true
}
