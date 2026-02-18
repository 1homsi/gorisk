// Package languages embeds the per-language capability pattern definitions.
// Each YAML file defines import paths and call-site substrings that map to
// capabilities, making it straightforward to add new language support by
// dropping in a new *.yaml file and registering the lang key in
// internal/analyzer/analyzer.go.
package languages

import "embed"

// FS is an embed.FS containing every *.yaml file in this directory.
//
//go:embed *.yaml
var FS embed.FS
