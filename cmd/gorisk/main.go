package main

import (
	"fmt"
	"os"

	"github.com/1homsi/gorisk/cmd/gorisk/capabilities"
	"github.com/1homsi/gorisk/cmd/gorisk/diff"
	graphcmd "github.com/1homsi/gorisk/cmd/gorisk/graph"
	"github.com/1homsi/gorisk/cmd/gorisk/impact"
	"github.com/1homsi/gorisk/cmd/gorisk/licenses"
	goriskpr "github.com/1homsi/gorisk/cmd/gorisk/pr"
	goriskreach "github.com/1homsi/gorisk/cmd/gorisk/reachability"
	"github.com/1homsi/gorisk/cmd/gorisk/sbom"
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
	case "reachability":
		os.Exit(goriskreach.Run(os.Args[2:]))
	case "pr":
		os.Exit(goriskpr.Run(os.Args[2:]))
	case "graph":
		os.Exit(graphcmd.Run(os.Args[2:]))
	case "sbom":
		os.Exit(sbom.Run(os.Args[2:]))
	case "licenses":
		os.Exit(licenses.Run(os.Args[2:]))
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
  gorisk capabilities   [--json] [--min-risk low|medium|high] [pattern]
  gorisk diff           [--json] <module@old> <module@new>
  gorisk upgrade        [--json] <module@version>
  gorisk impact         [--json] <module[@version]>
  gorisk scan           [--json] [--sarif] [--fail-on low|medium|high] [--policy file.json] [pattern]
  gorisk reachability   [--json] [--min-risk low|medium|high] [pattern]
  gorisk pr             [--json] [--base ref] [--head ref]
  gorisk graph          [--json] [--min-risk low|medium|high] [pattern]
  gorisk sbom           [--format cyclonedx] [pattern]
  gorisk licenses       [--json] [--fail-on-risky] [pattern]
  gorisk version`)
}
