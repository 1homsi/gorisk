// Package haskell implements a gorisk analyzer for Haskell projects.
// It supports cabal.project.freeze, stack.yaml.lock, and *.cabal files.
package haskell

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// HaskellPackage represents a Haskell dependency extracted from a lockfile.
type HaskellPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Haskell dependency lockfile in dir.
// Priority: cabal.project.freeze → stack.yaml.lock → *.cabal (glob top-level)
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []HaskellPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("haskell.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "cabal.project.freeze")):
		return loadCabalFreeze(dir)
	case fileExists(filepath.Join(dir, "stack.yaml.lock")):
		return loadStackLock(dir)
	}

	// Try *.cabal glob.
	matches, err := filepath.Glob(filepath.Join(dir, "*.cabal"))
	if err != nil {
		return nil, fmt.Errorf("glob *.cabal in %s: %w", dir, err)
	}
	if len(matches) > 0 {
		return loadCabalFile(matches[0])
	}

	return nil, fmt.Errorf("no Haskell lockfile found (looked for cabal.project.freeze, stack.yaml.lock, *.cabal) in %s", dir)
}

// ---------------------------------------------------------------------------
// cabal.project.freeze
// ---------------------------------------------------------------------------

// reCabalConstraint matches "any.NAME ==VERSION" or "NAME ==VERSION" lines.
var reCabalConstraint = regexp.MustCompile(`\bany\.([A-Za-z0-9_\-.]+)\s*==\s*([^\s,]+)`)
var reCabalConstraintBare = regexp.MustCompile(`^\s*([A-Za-z0-9_\-.]+)\s*==\s*([^\s,]+)`)

func loadCabalFreeze(dir string) ([]HaskellPackage, error) {
	path := filepath.Join(dir, "cabal.project.freeze")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	// Read direct deps from *.cabal if present.
	directDeps := readCabalDirectDeps(dir)

	seen := make(map[string]bool)
	var pkgs []HaskellPackage

	inConstraints := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		// "constraints:" header starts the block.
		if strings.HasPrefix(trimmed, "constraints:") {
			inConstraints = true
			// The header line itself may contain a constraint too.
			rest := strings.TrimPrefix(trimmed, "constraints:")
			extractFreezeConstraints(rest, &pkgs, seen, directDeps)
			continue
		}

		// A line that starts at column 0 (no leading whitespace) ends the constraints block.
		if inConstraints && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inConstraints = false
		}

		if inConstraints {
			extractFreezeConstraints(line, &pkgs, seen, directDeps)
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}
	return pkgs, nil
}

func extractFreezeConstraints(line string, pkgs *[]HaskellPackage, seen map[string]bool, directDeps map[string]bool) {
	// Try "any.NAME ==VERSION" pattern first.
	if m := reCabalConstraint.FindStringSubmatch(line); m != nil {
		name := strings.TrimSpace(m[1])
		version := strings.TrimRight(strings.TrimSpace(m[2]), ",")
		if name != "" && !seen[name] {
			seen[name] = true
			*pkgs = append(*pkgs, HaskellPackage{
				Name:    name,
				Version: version,
				Direct:  directDeps[name],
			})
		}
		return
	}
	// Try bare "NAME ==VERSION".
	stripped := strings.TrimSpace(line)
	stripped = strings.TrimPrefix(stripped, "any.")
	if m := reCabalConstraintBare.FindStringSubmatch(stripped); m != nil {
		name := strings.TrimSpace(m[1])
		version := strings.TrimRight(strings.TrimSpace(m[2]), ",")
		if name != "" && !seen[name] {
			seen[name] = true
			*pkgs = append(*pkgs, HaskellPackage{
				Name:    name,
				Version: version,
				Direct:  directDeps[name],
			})
		}
	}
}

// ---------------------------------------------------------------------------
// stack.yaml.lock
// ---------------------------------------------------------------------------

// reStackHackage matches lines like:
//
//	hackage: aeson-2.2.1.0@sha256:...,size:12345
//	hackage: aeson-2.2.1.0
var reStackHackage = regexp.MustCompile(`hackage:\s*([A-Za-z0-9_\-.]+)-(\d[^@\s]*)`)

func loadStackLock(dir string) ([]HaskellPackage, error) {
	path := filepath.Join(dir, "stack.yaml.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var pkgs []HaskellPackage

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		m := reStackHackage.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[1])
		version := strings.TrimSpace(m[2])
		// Strip anything after @.
		version, _, _ = strings.Cut(version, "@")
		version = strings.TrimSpace(version)

		if name != "" && !seen[name] {
			seen[name] = true
			pkgs = append(pkgs, HaskellPackage{
				Name:    name,
				Version: version,
				Direct:  false,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// *.cabal
// ---------------------------------------------------------------------------

// reBuildDepends matches package names in build-depends sections.
// Handles: "aeson ^>=2.1", "http-conduit >= 2.3", "base >=4.14 && <5"
var reBuildDepPkg = regexp.MustCompile(`^\s*([A-Za-z0-9_\-][A-Za-z0-9_\-.]*)\s*([,^>=<!]|$)`)

func loadCabalFile(path string) ([]HaskellPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var pkgs []HaskellPackage

	inBuildDepends := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		// Detect "build-depends:" section.
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "build-depends:") {
			inBuildDepends = true
			rest := trimmed[len("build-depends:"):]
			parseBuildDepsLine(rest, &pkgs, seen)
			continue
		}

		// End build-depends on a new field (no leading whitespace, contains colon, not comma).
		if inBuildDepends {
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inBuildDepends = false
				continue
			}
			parseBuildDepsLine(trimmed, &pkgs, seen)
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}
	return pkgs, nil
}

func parseBuildDepsLine(line string, pkgs *[]HaskellPackage, seen map[string]bool) {
	// Split by comma to handle multiple deps on one line.
	parts := strings.Split(line, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "--") {
			continue
		}

		m := reBuildDepPkg.FindStringSubmatch(part)
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[1])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		*pkgs = append(*pkgs, HaskellPackage{
			Name:   name,
			Direct: true,
		})
	}
}

// ---------------------------------------------------------------------------
// readCabalDirectDeps — read *.cabal for direct dep names
// ---------------------------------------------------------------------------

func readCabalDirectDeps(dir string) map[string]bool {
	matches, err := filepath.Glob(filepath.Join(dir, "*.cabal"))
	if err != nil || len(matches) == 0 {
		return nil
	}
	pkgs, err := loadCabalFile(matches[0])
	if err != nil || len(pkgs) == 0 {
		return nil
	}
	direct := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		direct[p.Name] = true
	}
	return direct
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
