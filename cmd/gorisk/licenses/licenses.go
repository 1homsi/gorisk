package licenses

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/license"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("licenses", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	failOnRisky := fs.Bool("fail-on-risky", false, "exit 1 if any risky license found")
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

	seen := make(map[string]bool)
	var reports []license.LicenseReport
	for _, mod := range g.Modules {
		if mod.Main || seen[mod.Path] {
			continue
		}
		seen[mod.Path] = true
		reports = append(reports, license.Detect(mod.Path, mod.Version))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if reports == nil {
			reports = []license.LicenseReport{}
		}
		enc.Encode(reports)
		return 0
	}

	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		bold   = "\033[1m"
		reset  = "\033[0m"
	)

	fmt.Printf("%s%-60s  %-20s  %s\n", bold, "MODULE", "LICENSE", "STATUS"+reset)
	fmt.Println(string(make([]byte, 100)))

	hasRisky := false
	for _, r := range reports {
		status := green + "OK" + reset
		if r.Risky {
			hasRisky = true
			if r.License == "unknown" {
				status = yellow + "UNKNOWN" + reset
			} else {
				status = red + "RISKY — " + r.Reason + reset
			}
		}
		fmt.Printf("%-60s  %-20s  %s\n", r.Module, r.License, status)
	}

	if len(reports) == 0 {
		fmt.Println("no external modules found")
	}

	if *failOnRisky && hasRisky {
		fmt.Fprintln(os.Stderr, "✗ FAILED: risky licenses detected")
		return 1
	}
	return 0
}
