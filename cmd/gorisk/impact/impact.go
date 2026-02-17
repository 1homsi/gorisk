package impact

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/graph"
	impactlib "github.com/1homsi/gorisk/internal/impact"
	"github.com/1homsi/gorisk/internal/report"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("impact", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: gorisk impact <module[@version]>")
		return 2
	}

	target := fs.Arg(0)
	modulePath := target
	if at := strings.LastIndex(target, "@"); at != -1 {
		modulePath = target[:at]
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

	r := impactlib.Compute(g, modulePath)

	if *jsonOut {
		if err := report.WriteImpactJSON(os.Stdout, r); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			return 2
		}
	} else {
		report.WriteImpact(os.Stdout, r)
	}

	if len(r.AffectedMains) > 0 {
		return 1
	}
	return 0
}
