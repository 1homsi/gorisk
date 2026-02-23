// Package ocaml implements a gorisk analyzer for OCaml/opam projects.
// It supports *.opam.locked, opam.locked, and *.opam files.
package ocaml

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OCamlPackage represents an OCaml dependency extracted from an opam lockfile.
type OCamlPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the OCaml dependency lockfile in dir.
// Priority: *.opam.locked → opam.locked → *.opam (fallback).
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []OCamlPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("ocaml.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	// 1. *.opam.locked glob
	if path, ok := findFile(dir, "*.opam.locked"); ok {
		return loadOpamLocked(path, dir)
	}

	// 2. opam.locked
	if path := filepath.Join(dir, "opam.locked"); fileExists(path) {
		return loadOpamLocked(path, dir)
	}

	// 3. *.opam fallback
	if path, ok := findFile(dir, "*.opam"); ok {
		return loadOpam(path)
	}

	return nil, fmt.Errorf("no OCaml lockfile found (looked for *.opam.locked, opam.locked, *.opam) in %s", dir)
}

// ---------------------------------------------------------------------------
// opam.locked / *.opam.locked
// ---------------------------------------------------------------------------

// loadOpamLocked parses an opam locked file for the full dependency closure.
// It also reads direct deps from a matching *.opam source file.
func loadOpamLocked(path, dir string) ([]OCamlPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	directDeps := readOpamDirectDeps(dir, path)

	var pkgs []OCamlPackage
	inDepends := false

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Start of depends block.
		if strings.HasPrefix(trimmed, "depends:") && strings.Contains(trimmed, "[") {
			inDepends = true
			// Check if it closes on the same line.
			if strings.Contains(trimmed, "]") {
				inDepends = false
			}
			continue
		}

		// End of depends block.
		if inDepends && trimmed == "]" {
			inDepends = false
			continue
		}

		if !inDepends {
			continue
		}

		// Parse dependency line: `"name" {= "version" ...}` or `"name" {= "version"}`
		name, version := parseOpamDepLine(trimmed)
		if name == "" {
			continue
		}

		pkgs = append(pkgs, OCamlPackage{
			Name:    name,
			Version: version,
			Direct:  directDeps[name],
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return pkgs, nil
}

// parseOpamDepLine extracts the package name and version from a depends-block line.
// Expected formats:
//
//	"name" {= "0.1.2"}
//	"name" {= "0.1.2" & preinstalled}
//	"name" {>= "0.1.2"}
//	"name"
func parseOpamDepLine(line string) (name, version string) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, `"`) {
		return "", ""
	}

	// Extract the first quoted token — the package name.
	rest := line[1:] // strip leading "
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", ""
	}
	name = rest[:end]
	if name == "" {
		return "", ""
	}
	rest = rest[end+1:] // after closing "

	// Look for = "VERSION".
	if idx := strings.Index(rest, `= "`); idx >= 0 {
		vRest := rest[idx+3:]
		vEnd := strings.Index(vRest, `"`)
		if vEnd >= 0 {
			version = vRest[:vEnd]
		}
	}

	return name, version
}

// ---------------------------------------------------------------------------
// *.opam (source / fallback)
// ---------------------------------------------------------------------------

// loadOpam parses a source .opam file, returning all deps as Direct=true
// with no version constraints resolved (version left empty).
func loadOpam(path string) ([]OCamlPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []OCamlPackage
	seen := make(map[string]bool)
	inDepends := false

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "depends:") && strings.Contains(trimmed, "[") {
			inDepends = true
			if strings.Contains(trimmed, "]") {
				inDepends = false
			}
			continue
		}
		if inDepends && trimmed == "]" {
			inDepends = false
			continue
		}
		if !inDepends {
			continue
		}

		name, version := parseOpamDepLine(trimmed)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, OCamlPackage{
			Name:    name,
			Version: version,
			Direct:  true,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return pkgs, nil
}

// ---------------------------------------------------------------------------
// readOpamDirectDeps — read direct deps from matching *.opam file
// ---------------------------------------------------------------------------

// readOpamDirectDeps returns the set of package names listed in the depends:
// section of a source .opam file (without = version constraints).
// The locked file path is used to locate the matching source .opam file.
func readOpamDirectDeps(dir, lockedPath string) map[string]bool {
	// Derive the corresponding source .opam file name.
	// e.g. "foo.opam.locked" → "foo.opam", "opam.locked" → first *.opam found.
	base := filepath.Base(lockedPath)
	var srcPath string
	switch {
	case strings.HasSuffix(base, ".opam.locked"):
		srcName := strings.TrimSuffix(base, ".locked")
		srcPath = filepath.Join(dir, srcName)
	default:
		// opam.locked — look for any *.opam
		if p, ok := findFile(dir, "*.opam"); ok {
			srcPath = p
		}
	}

	if srcPath == "" || !fileExists(srcPath) {
		return nil
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return nil
	}

	direct := make(map[string]bool)
	inDepends := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "depends:") && strings.Contains(trimmed, "[") {
			inDepends = true
			if strings.Contains(trimmed, "]") {
				inDepends = false
			}
			continue
		}
		if inDepends && trimmed == "]" {
			inDepends = false
			continue
		}
		if !inDepends {
			continue
		}

		name, _ := parseOpamDepLine(trimmed)
		if name != "" {
			direct[name] = true
		}
	}
	return direct
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// findFile returns the first file matching pattern (glob) inside dir.
func findFile(dir, pattern string) (string, bool) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(matches) == 0 {
		return "", false
	}
	return matches[0], true
}

// fileExists reports whether path exists on disk.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
