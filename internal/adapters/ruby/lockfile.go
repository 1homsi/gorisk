package ruby

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RubyPackage represents a Ruby dependency extracted from a lockfile.
type RubyPackage struct {
	Name         string
	Version      string
	Dir          string
	Dependencies []string
	Direct       bool
}

// Load detects and parses the Ruby dependency lockfile in dir.
// Tries Gemfile.lock first, then falls back to Gemfile.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []RubyPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("ruby.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "Gemfile.lock")):
		return loadGemfileLock(dir)
	case fileExists(filepath.Join(dir, "Gemfile")):
		return loadGemfile(dir)
	}
	return nil, fmt.Errorf("no Ruby lockfile found (looked for Gemfile.lock, Gemfile) in %s", dir)
}

// ---------------------------------------------------------------------------
// Gemfile.lock
// ---------------------------------------------------------------------------

// Gemfile.lock format:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    rails (7.1.0)
//	      actioncable (= 7.1.0)
//	      ...
//
//	DEPENDENCIES
//	  rails (~> 7.1.0)
func loadGemfileLock(dir string) ([]RubyPackage, error) {
	path := filepath.Join(dir, "Gemfile.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	directDeps := readGemfileDirectDeps(dir)

	// State machine: sections we care about.
	const (
		sectionNone  = ""
		sectionSpecs = "specs"
		sectionDeps  = "dependencies"
	)

	var packages []RubyPackage
	byName := make(map[string]*RubyPackage)

	section := sectionNone
	var curPkg *RubyPackage

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Section headers (no leading whitespace).
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			switch strings.TrimRight(trimmed, ":") {
			case "GEM", "GIT", "PATH":
				section = sectionNone
				curPkg = nil
			case "DEPENDENCIES":
				section = sectionDeps
				curPkg = nil
			}
			continue
		}

		// "    specs:" sub-header inside GEM/GIT/PATH.
		if trimmed == "specs:" {
			section = sectionSpecs
			curPkg = nil
			continue
		}

		if section == sectionSpecs {
			indent := leadingSpaces(line)
			if indent == 0 || trimmed == "" {
				curPkg = nil
				continue
			}

			// Gem definition line: "    rails (7.1.0)" (4 spaces)
			if indent == 4 {
				name, version := parseGemSpec(trimmed)
				if name == "" {
					continue
				}
				pkg := RubyPackage{
					Name:    name,
					Version: version,
					Direct:  directDeps[name],
				}
				packages = append(packages, pkg)
				byName[name] = &packages[len(packages)-1]
				curPkg = byName[name]
				continue
			}

			// Dependency of current gem: "      actioncable (= 7.1.0)" (6+ spaces)
			if indent >= 6 && curPkg != nil {
				depName, _ := parseGemSpec(trimmed)
				if depName != "" {
					curPkg.Dependencies = append(curPkg.Dependencies, depName)
				}
				continue
			}
		}

		// DEPENDENCIES section: list of direct deps.
		if section == sectionDeps {
			depName, _ := parseGemSpec(trimmed)
			if depName != "" && byName[depName] != nil {
				byName[depName].Direct = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return packages, nil
}

// parseGemSpec parses a gem spec line like "rails (7.1.0)" or "rails (~> 7.1.0)".
// Returns name and version string (version may be empty).
func parseGemSpec(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	before, rest, ok := strings.Cut(s, "(")
	if !ok {
		// No version — just a name (e.g. in DEPENDENCIES without constraint).
		return strings.TrimSpace(s), ""
	}
	name = strings.TrimSpace(before)
	// Strip constraint operators like "~>", ">=", "=", "!="
	rest = strings.TrimRight(rest, ")")
	// Remove leading operator tokens.
	for _, op := range []string{"~> ", ">= ", "<= ", "!= ", "= ", "> ", "< "} {
		rest, _ = strings.CutPrefix(rest, op)
	}
	version = strings.TrimSpace(rest)
	return name, version
}

// leadingSpaces counts the number of leading spaces in a line.
func leadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 4 // treat tab as 4 spaces for indentation purposes
		default:
			return count
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Gemfile (minimal — no lockfile)
// ---------------------------------------------------------------------------

// loadGemfile parses a Gemfile for gem declarations.
// Handles: gem 'name', gem 'name', '~> version', gem "name"
func loadGemfile(dir string) ([]RubyPackage, error) {
	path := filepath.Join(dir, "Gemfile")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []RubyPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "gem ") && !strings.HasPrefix(line, "gem\t") {
			continue
		}
		name, version := parseGemfileLine(line)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		packages = append(packages, RubyPackage{
			Name:    name,
			Version: version,
			Direct:  true,
		})
	}
	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return packages, nil
}

// parseGemfileLine extracts the gem name and optional version from a Gemfile
// "gem ..." line.
func parseGemfileLine(line string) (name, version string) {
	if len(line) < 4 {
		return "", ""
	}
	// Strip "gem " prefix.
	rest := strings.TrimSpace(line[4:])
	// Split by comma to get individual arguments.
	args := splitGemArgs(rest)
	if len(args) == 0 {
		return "", ""
	}
	name = strings.Trim(args[0], `"' `)
	if len(args) >= 2 {
		v := strings.Trim(args[1], `"' `)
		// Strip constraint operator.
		for _, op := range []string{"~> ", ">= ", "<= ", "!= ", "= ", "> ", "< "} {
			v, _ = strings.CutPrefix(v, op)
		}
		version = v
	}
	return name, version
}

// splitGemArgs splits a gem argument string by commas, respecting quoted strings.
func splitGemArgs(s string) []string {
	var args []string
	var buf strings.Builder
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
			}
			buf.WriteByte(ch)
		} else if ch == '\'' || ch == '"' {
			inQuote = ch
			buf.WriteByte(ch)
		} else if ch == ',' {
			args = append(args, strings.TrimSpace(buf.String()))
			buf.Reset()
		} else {
			buf.WriteByte(ch)
		}
	}
	if buf.Len() > 0 {
		args = append(args, strings.TrimSpace(buf.String()))
	}
	return args
}

// ---------------------------------------------------------------------------
// readGemfileDirectDeps — read Gemfile for direct dep names
// ---------------------------------------------------------------------------

// readGemfileDirectDeps returns the set of gem names declared in Gemfile.
func readGemfileDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "Gemfile"))
	if err != nil {
		return nil
	}
	direct := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "gem ") && !strings.HasPrefix(line, "gem\t") {
			continue
		}
		name, _ := parseGemfileLine(line)
		if name != "" {
			direct[name] = true
		}
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
