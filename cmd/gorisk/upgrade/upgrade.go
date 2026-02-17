package upgrade

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1homsi/gorisk/internal/report"
	upgradelib "github.com/1homsi/gorisk/internal/upgrade"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: gorisk upgrade <module@version>")
		return 2
	}

	modulePath, version, ok := splitAt(fs.Arg(0))
	if !ok {
		fmt.Fprintln(os.Stderr, "specify version: module@version")
		return 2
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	r, err := upgradelib.Analyze(dir, modulePath, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upgrade analysis:", err)
		return 2
	}

	if *jsonOut {
		if err := report.WriteUpgradeJSON(os.Stdout, r); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			return 2
		}
	} else {
		report.WriteUpgrade(os.Stdout, r)
	}

	if r.Risk == "HIGH" {
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
