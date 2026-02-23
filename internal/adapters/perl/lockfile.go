// Package perl implements a gorisk analyzer for Perl projects.
// It supports cpanfile.snapshot (Carton) and cpanfile.
package perl

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PerlPackage represents a Perl dependency extracted from a lockfile.
type PerlPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Perl dependency manifest in dir.
// Tries cpanfile.snapshot first, then falls back to cpanfile.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []PerlPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("perl.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "cpanfile.snapshot")):
		return loadCpanfileSnapshot(dir)
	case fileExists(filepath.Join(dir, "cpanfile")):
		return loadCpanfile(dir)
	}
	return nil, fmt.Errorf("no Perl lockfile found (looked for cpanfile.snapshot, cpanfile) in %s", dir)
}

// ---------------------------------------------------------------------------
// cpanfile.snapshot (Carton)
// ---------------------------------------------------------------------------

// loadCpanfileSnapshot parses a Carton cpanfile.snapshot file.
//
// Format example:
//
//	# carton snapshot format: version 1.0
//	DISTRIBUTIONS
//	  Carp-1.50
//	    pathname: C/CG/CGMORTON/Carp-1.50.tar.gz
//	    provides:
//	      Carp 1.50
//	    requirements:
//	      perl 5.008001
func loadCpanfileSnapshot(dir string) ([]PerlPackage, error) {
	path := filepath.Join(dir, "cpanfile.snapshot")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	directSet := readCpanfileDirectDeps(dir)

	var pkgs []PerlPackage
	seen := make(map[string]bool)

	// State machine sections.
	const (
		sectionNone    = ""
		sectionProvide = "provides"
		sectionReq     = "requirements"
	)

	var curPkg *PerlPackage
	var curDist string
	var curDistVer string
	section := sectionNone

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "DISTRIBUTIONS" {
			continue
		}

		indent := leadingSpaces(line)

		switch indent {
		case 2:
			// Distribution line: "  Name-Version"
			curPkg = nil
			section = sectionNone
			curDist, curDistVer = splitDistVersion(trimmed)
			_ = curDistVer
		case 4:
			// Sub-fields of a distribution.
			switch trimmed {
			case "provides:":
				section = sectionProvide
			case "requirements:":
				section = sectionReq
			}
		case 6:
			// Content of provides: or requirements:
			if section == sectionProvide {
				// "      Module::Name VERSION"
				parts := strings.Fields(trimmed)
				if len(parts) >= 1 {
					modName := parts[0]
					if modName == "perl" {
						continue
					}
					ver := ""
					if len(parts) >= 2 {
						ver = parts[1]
					}
					key := modName
					if !seen[key] {
						seen[key] = true
						pkgs = append(pkgs, PerlPackage{
							Name:    modName,
							Version: ver,
							Direct:  directSet[modName] || directSet[curDist],
						})
						curPkg = &pkgs[len(pkgs)-1]
					} else {
						// Find existing package to set as curPkg.
						for i := range pkgs {
							if pkgs[i].Name == key {
								curPkg = &pkgs[i]
								break
							}
						}
					}
					_ = curPkg
				}
			}
			// requirements: lines are not currently tracked as dependencies.
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return pkgs, nil
}

// splitDistVersion splits a distribution name like "Carp-1.50" into
// ("Carp", "1.50"). Handles multi-part names like "LWP-UserAgent-6.67".
// The version is identified as the last "-X.Y..." suffix where X starts a digit.
func splitDistVersion(dist string) (name, version string) {
	// Walk backwards to find the last '-' followed by a digit.
	for i := len(dist) - 1; i >= 0; i-- {
		if dist[i] == '-' && i+1 < len(dist) && dist[i+1] >= '0' && dist[i+1] <= '9' {
			return dist[:i], dist[i+1:]
		}
	}
	return dist, ""
}

// ---------------------------------------------------------------------------
// cpanfile (direct deps)
// ---------------------------------------------------------------------------

// loadCpanfile parses a cpanfile for direct Perl dependencies.
// All packages are Direct=true.
func loadCpanfile(dir string) ([]PerlPackage, error) {
	path := filepath.Join(dir, "cpanfile")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	names := parseCpanfileRequires(data)
	if len(names) == 0 {
		return nil, nil
	}

	pkgs := make([]PerlPackage, 0, len(names))
	for name, ver := range names {
		pkgs = append(pkgs, PerlPackage{
			Name:    name,
			Version: ver,
			Direct:  true,
		})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// cpanfile helpers
// ---------------------------------------------------------------------------

// readCpanfileDirectDeps returns the set of module names listed with
// "requires" in a cpanfile.
func readCpanfileDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "cpanfile"))
	if err != nil {
		return nil
	}
	names := parseCpanfileRequires(data)
	if len(names) == 0 {
		return nil
	}
	direct := make(map[string]bool, len(names))
	for n := range names {
		direct[n] = true
	}
	return direct
}

// parseCpanfileRequires extracts module name → version from "requires '...'"
// and "requires '...', '...'" lines in a cpanfile.
func parseCpanfileRequires(data []byte) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Match: requires 'Module::Name'; or requires 'Module::Name', '1.0';
		// Also handles double-quoted variants.
		if !strings.HasPrefix(line, "requires ") && !strings.HasPrefix(line, "requires\t") {
			continue
		}
		rest := strings.TrimSpace(line[len("requires"):])
		name, ver := parseCpanRequiresArgs(rest)
		if name != "" && name != "perl" {
			result[name] = ver
		}
	}
	return result
}

// parseCpanRequiresArgs extracts the module name and optional version from
// the argument portion of a cpanfile "requires" line.
// e.g. "'LWP::UserAgent', '6.0';" → ("LWP::UserAgent", "6.0")
func parseCpanRequiresArgs(s string) (name, version string) {
	// Strip trailing semicolons and whitespace.
	s = strings.TrimRight(s, "; \t")
	if s == "" {
		return "", ""
	}
	// Split by comma.
	parts := strings.SplitN(s, ",", 2)
	name = strings.Trim(parts[0], `"' `)
	if len(parts) == 2 {
		version = strings.Trim(parts[1], `"' `)
	}
	return name, version
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// leadingSpaces counts the number of leading spaces in a line.
func leadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 4
		default:
			return count
		}
	}
	return count
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
