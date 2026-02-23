// Package clojure implements a gorisk analyzer for Clojure projects.
// It supports deps.edn (tools.deps) and project.clj (Leiningen).
package clojure

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ClojurePackage represents a Clojure/Maven dependency extracted from a lockfile.
type ClojurePackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Clojure dependency file in dir.
// Priority: deps.edn → project.clj.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []ClojurePackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("clojure.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "deps.edn")):
		return loadDepsEdn(dir)
	case fileExists(filepath.Join(dir, "project.clj")):
		return loadProjectClj(dir)
	}
	return nil, fmt.Errorf("no Clojure dependency file found (looked for deps.edn, project.clj) in %s", dir)
}

// ---------------------------------------------------------------------------
// deps.edn
// ---------------------------------------------------------------------------

// loadDepsEdn parses a deps.edn file using a line scanner.
// Lines containing {:mvn/version "X"} are picked up; the artifact symbol
// before the map is used as the package name.
// Packages in :aliases sub-sections are treated as indirect (dev/test).
func loadDepsEdn(dir string) ([]ClojurePackage, error) {
	path := filepath.Join(dir, "deps.edn")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []ClojurePackage
	seen := make(map[string]bool)

	// Track whether we are inside an :aliases block.
	// A simple heuristic: once we see ":aliases" on a line we treat subsequent
	// mvn/version entries as indirect until end of file.
	inAliases := false

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if strings.Contains(line, ":aliases") {
			inAliases = true
		}

		// Look for {:mvn/version "X"} on this line.
		const marker = `{:mvn/version "`
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}

		// Extract version string.
		rest := line[idx+len(marker):]
		vEnd := strings.IndexByte(rest, '"')
		if vEnd < 0 {
			continue
		}
		version := rest[:vEnd]

		// Extract the symbol that precedes the map on this line.
		// The symbol is the last non-whitespace token before the map open brace.
		prefix := strings.TrimRight(line[:idx], " \t")
		// Strip any leading [ or { characters (EDN vector/map opening).
		prefix = strings.TrimLeft(prefix, "[{ \t")
		// The symbol is the last whitespace-delimited token.
		name := lastToken(prefix)
		if name == "" {
			continue
		}
		// Normalise: strip surrounding EDN punctuation.
		name = strings.Trim(name, "[]{}()'\"")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, ClojurePackage{
			Name:    name,
			Version: version,
			Direct:  !inAliases,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// lastToken returns the last whitespace-delimited token in s.
func lastToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	idx := strings.LastIndexAny(s, " \t")
	if idx < 0 {
		return s
	}
	return s[idx+1:]
}

// ---------------------------------------------------------------------------
// project.clj (Leiningen)
// ---------------------------------------------------------------------------

// loadProjectClj parses a project.clj file for :dependencies entries.
// Handles vector entries of the form [group/artifact "version"] or
// [artifact "version"].  All packages are treated as direct dependencies.
func loadProjectClj(dir string) ([]ClojurePackage, error) {
	path := filepath.Join(dir, "project.clj")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []ClojurePackage
	seen := make(map[string]bool)

	inDeps := false
	bracketDepth := 0

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !inDeps {
			if !strings.Contains(trimmed, ":dependencies") {
				continue
			}
			inDeps = true
			// Do NOT continue — fall through to process this line.
			// The :dependencies line may already contain the first entry, e.g.:
			//   :dependencies [[org.clojure/clojure "1.11.1"]
		}

		// Accumulate bracket depth for this line.
		bracketDepth += strings.Count(line, "[") - strings.Count(line, "]")

		// Scan for [NAME "VERSION"] entries on this line.
		rest := trimmed
		for {
			start := strings.IndexByte(rest, '[')
			if start < 0 {
				break
			}
			end := strings.IndexByte(rest[start:], ']')
			if end < 0 {
				break
			}
			inner := rest[start+1 : start+end]
			name, version := parseLeinDep(inner)
			if name != "" && !seen[name] {
				seen[name] = true
				pkgs = append(pkgs, ClojurePackage{
					Name:    name,
					Version: version,
					Direct:  true,
				})
			}
			rest = rest[start+end+1:]
		}

		if bracketDepth <= 0 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// parseLeinDep parses a Leiningen dependency vector body such as:
//
//	org.clojure/clojure "1.11.1"
//	[org.clojure/clojure "1.11.1"    (outer vector on same line — leading [ stripped)
//	ring/ring-core "1.11.0"
//	compojure "1.7.1"
//
// Returns the artifact name and version string.
func parseLeinDep(inner string) (name, version string) {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return "", ""
	}
	// Strip any leading bracket that appears when the outer dependency vector
	// opens on the same line as the first entry: "[[artifact \"ver\"]".
	inner = strings.TrimLeft(inner, "[ \t")
	fields := strings.Fields(inner)
	if len(fields) < 1 {
		return "", ""
	}
	name = strings.Trim(fields[0], `"'`)
	if len(fields) >= 2 {
		version = strings.Trim(fields[1], `"'`)
	}
	// Reject names that are keywords or obviously not artifact IDs.
	if strings.HasPrefix(name, ":") || name == "" {
		return "", ""
	}
	return name, version
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
