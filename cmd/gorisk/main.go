package main

import (
	"fmt"
	"os"

	"github.com/1homsi/gorisk/cmd/gorisk/capabilities"
	"github.com/1homsi/gorisk/cmd/gorisk/diff"
	"github.com/1homsi/gorisk/cmd/gorisk/impact"
	"github.com/1homsi/gorisk/cmd/gorisk/scan"
	"github.com/1homsi/gorisk/cmd/gorisk/upgrade"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "capabilities":
		os.Exit(capabilities.Run(os.Args[2:]))
	case "diff":
		os.Exit(diff.Run(os.Args[2:]))
	case "upgrade":
		os.Exit(upgrade.Run(os.Args[2:]))
	case "impact":
		os.Exit(impact.Run(os.Args[2:]))
	case "scan":
		os.Exit(scan.Run(os.Args[2:]))
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `gorisk — Go dependency risk analyzer

Usage:
  gorisk capabilities [--json] [--min-risk low|medium|high] [pattern]
  gorisk diff         [--json] <module@old> <module@new>
  gorisk upgrade      [--json] <module@version>
  gorisk impact       [--json] <module[@version]>
  gorisk scan         [--json] [--sarif] [--fail-on low|medium|high] [--policy file.json] [pattern]
  gorisk version`)
}
