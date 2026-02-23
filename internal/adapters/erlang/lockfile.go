// Package erlang implements a gorisk analyzer for Erlang projects.
// It supports rebar.lock and rebar.config.
package erlang

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErlangPackage represents an Erlang dependency extracted from a lockfile.
type ErlangPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// rebarLockEntry matches lines in rebar.lock of the form:
//
//	{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>,...},0},
//
// Group 1 = name, group 2 = version, group 3 = depth integer.
var rebarLockEntry = regexp.MustCompile(
	`\{<<"([^"]+)">>,\{pkg,<<"[^"]*">>,<<"([^"]+)">>`,
)

// rebarLockDepth extracts the trailing depth integer from a rebar.lock entry
// line. It looks for the last comma-separated integer before the closing }.
var rebarLockDepth = regexp.MustCompile(`,(\d+)\}`)

// rebarConfigDep matches simple {name, "version"} entries in rebar.config.
var rebarConfigDep = regexp.MustCompile(`\{(\w+)\s*,\s*"([^"]+)"\s*\}`)

// Load detects and parses the Erlang dependency file in dir.
// Priority: rebar.lock → rebar.config.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []ErlangPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("erlang.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "rebar.lock")):
		return loadRebarLock(dir)
	case fileExists(filepath.Join(dir, "rebar.config")):
		return loadRebarConfig(dir)
	}
	return nil, fmt.Errorf("no Erlang dependency file found (looked for rebar.lock, rebar.config) in %s", dir)
}

// ---------------------------------------------------------------------------
// rebar.lock
// ---------------------------------------------------------------------------

// loadRebarLock parses a rebar.lock file using a line scanner.
//
// Example format:
//
//	{"1.2.0",
//	[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>,<<"sha256:...">>,<<"sha256:...">>},0},
//	 {<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>,<<"sha256:...">>,<<"sha256:...">>},1}
//	]}.
//
// Depth 0 = direct, depth > 0 = transitive.
func loadRebarLock(dir string) ([]ErlangPackage, error) {
	path := filepath.Join(dir, "rebar.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []ErlangPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		m := rebarLockEntry.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		version := m[2]
		if seen[name] {
			continue
		}

		// Extract depth from the end of the line.
		direct := false
		dm := rebarLockDepth.FindAllStringSubmatch(line, -1)
		if len(dm) > 0 {
			last := dm[len(dm)-1][1]
			direct = last == "0"
		}

		seen[name] = true
		pkgs = append(pkgs, ErlangPackage{
			Name:    name,
			Version: version,
			Direct:  direct,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// rebar.config
// ---------------------------------------------------------------------------

// loadRebarConfig parses a rebar.config file for the {deps, [...]} section.
// Only handles simple {name, "version"} entries; git deps use the name only.
func loadRebarConfig(dir string) ([]ErlangPackage, error) {
	path := filepath.Join(dir, "rebar.config")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []ErlangPackage
	seen := make(map[string]bool)

	inDeps := false
	braceDepth := 0

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !inDeps {
			if strings.HasPrefix(trimmed, "{deps,") || strings.Contains(trimmed, "{deps,") {
				inDeps = true
				braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			}
			continue
		}

		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		// Match {name, "version"} entries on this line.
		matches := rebarConfigDep.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			name := m[1]
			version := m[2]
			if seen[name] {
				continue
			}
			seen[name] = true
			pkgs = append(pkgs, ErlangPackage{
				Name:    name,
				Version: version,
				Direct:  true,
			})
		}

		// Also capture git deps: {name, {git, ...}} — extract name only.
		gitDeps := extractGitDepNames(line)
		for _, name := range gitDeps {
			if seen[name] {
				continue
			}
			seen[name] = true
			pkgs = append(pkgs, ErlangPackage{
				Name:   name,
				Direct: true,
			})
		}

		if braceDepth <= 0 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// rebarGitDep matches git dependency entries like:
//
//	{hackney, {git, "https://...", {tag, "1.20.1"}}}
var rebarGitDep = regexp.MustCompile(`\{(\w+)\s*,\s*\{git\b`)

// extractGitDepNames returns the names of git-sourced deps on a rebar.config line.
func extractGitDepNames(line string) []string {
	matches := rebarGitDep.FindAllStringSubmatch(line, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
