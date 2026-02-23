// Package initcmd provides the gorisk init command, which writes a commented
// .gorisk-policy.json template to the current directory.
package initcmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

const policyFileName = ".gorisk-policy.json"

// policyTemplate is the default policy written by gorisk init.
// Fields match the policy struct in cmd/gorisk/scan/scan.go.
var policyTemplate = map[string]any{
	"version":              1,
	"fail_on":              "high",
	"confidence_threshold": 0.65,
	"deny_capabilities":    []any{},
	"allow_exceptions":     []any{},
	"exclude_packages":     []any{},
	"max_dep_depth":        0,
	"suppress": map[string]any{
		"by_file_pattern":   []any{},
		"by_module":         []any{},
		"by_capability_via": []any{},
	},
}

// Run is the entry point for the `gorisk init` subcommand.
func Run(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing policy file")
	stdout := fs.Bool("stdout", false, "print policy to stdout instead of writing a file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	data, err := json.MarshalIndent(policyTemplate, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal policy template:", err)
		return 2
	}
	data = append(data, '\n')

	if *stdout {
		_, err := os.Stdout.Write(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			return 2
		}
		return 0
	}

	if !*force {
		if _, err := os.Stat(policyFileName); err == nil {
			fmt.Fprintf(os.Stderr, "%s already exists; use --force to overwrite\n", policyFileName)
			return 1
		}
	}

	if err := os.WriteFile(policyFileName, data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write policy file:", err)
		return 2
	}

	fmt.Fprintf(os.Stdout, "wrote %s\n", policyFileName)
	fmt.Fprintln(os.Stdout, "edit it to configure risk thresholds, denied capabilities, and exceptions.")
	return 0
}
