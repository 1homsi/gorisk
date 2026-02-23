package rust

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// rustPatterns holds the Rust PatternSet loaded from languages/rust.yaml.
var rustPatterns = capability.MustLoadPatterns("rust")

// Detect walks .rs files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".rs" {
			scanRsFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanRsFile scans a single Rust source file for capability evidence.
func scanRsFile(path string, caps *capability.CapabilitySet) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		trimmed := strings.TrimSpace(line)

		// Match use/extern crate statements.
		if strings.HasPrefix(trimmed, "use ") || strings.HasPrefix(trimmed, "extern crate ") {
			checkRustImport(line, caps, path, lineNo)
			continue
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range rustPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    strings.TrimSpace(line),
						Via:        "callSite",
						Confidence: 0.60,
					})
				}
			}
		}
	}
}

// checkRustImport detects capabilities from Rust use/extern crate statements.
func checkRustImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	var moduleName string
	if rest, ok := strings.CutPrefix(trimmed, "use "); ok {
		// "use std::fs::File;" → module root is "std::fs"
		// Strip trailing "; " and any "as" alias.
		rest = strings.TrimRight(strings.TrimSpace(rest), ";")
		// Handle glob: "use std::io::*;"
		rest = strings.TrimSuffix(rest, "::*")
		// Handle braces: "use std::{fs, io};" → use top-level "std"
		if idx := strings.Index(rest, "{"); idx >= 0 {
			rest = strings.TrimRight(rest[:idx], ":")
		}
		// Handle "as" alias: "use reqwest as http;"
		if idx := strings.Index(rest, " as "); idx >= 0 {
			rest = rest[:idx]
		}
		moduleName = strings.TrimRight(strings.TrimSpace(rest), ";")
	} else if rest, ok := strings.CutPrefix(trimmed, "extern crate "); ok {
		// "extern crate serde;" → "serde"
		moduleName = strings.TrimRight(strings.TrimSpace(rest), ";")
	}

	if moduleName == "" {
		return
	}

	// Try progressively shorter module paths (std::fs::File → std::fs → std).
	// Also normalise :: to :: for lookup.
	addRustImportCaps(moduleName, line, caps, path, lineNo)

	// Shorten path by removing last segment.
	for {
		idx := strings.LastIndex(moduleName, "::")
		if idx < 0 {
			break
		}
		moduleName = moduleName[:idx]
		if moduleName == "" {
			break
		}
		addRustImportCaps(moduleName, line, caps, path, lineNo)
	}
}

func addRustImportCaps(moduleName, line string, caps *capability.CapabilitySet, path string, lineNo int) {
	importCaps, ok := rustPatterns.Imports[moduleName]
	if !ok {
		return
	}
	for _, c := range importCaps {
		caps.AddWithEvidence(c, capability.CapabilityEvidence{
			File:       path,
			Line:       lineNo,
			Context:    strings.TrimSpace(line),
			Via:        "import",
			Confidence: 0.90,
		})
	}
}
