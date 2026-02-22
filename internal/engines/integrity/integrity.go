// Package integrity validates checksum and integrity metadata in lockfiles.
package integrity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Violation represents a single integrity problem found in the lockfile.
type Violation struct {
	Package string
	Type    string // "missing_integrity" | "path_dep" | "git_dep" | "missing_checksum" | "local_replace" | "git_replace"
	Detail  string
	Score   float64
}

// IntegrityReport holds all integrity findings and the resulting score.
type IntegrityReport struct {
	TotalPackages int
	Coverage      float64 // % of packages with integrity metadata (0–100)
	Violations    []Violation
	Score         float64 // 0–20
}

// Check runs the integrity engine for the given directory and language.
func Check(dir, lang string) (IntegrityReport, error) {
	resolved, err := resolveLang(dir, lang)
	if err != nil {
		return IntegrityReport{}, err
	}
	switch resolved {
	case "go":
		return checkGo(dir)
	case "node":
		return checkNode(dir)
	default:
		return IntegrityReport{}, fmt.Errorf("unsupported language: %s", resolved)
	}
}

func resolveLang(dir, lang string) (string, error) {
	if lang != "auto" {
		return lang, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return "go", nil
	}
	for _, lf := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, lf)); err == nil {
			return "node", nil
		}
	}
	return "", fmt.Errorf("could not detect language in %s", dir)
}

// ---------------------------------------------------------------------------
// Go implementation
// ---------------------------------------------------------------------------

func checkGo(dir string) (IntegrityReport, error) {
	r := IntegrityReport{}

	requires, replaces, err := parseGoMod(dir)
	if err != nil {
		return r, fmt.Errorf("parse go.mod: %w", err)
	}

	checksums, err := parseGoSum(dir)
	if err != nil {
		// go.sum missing is itself a signal but not a fatal error.
		checksums = make(map[string]bool)
	}

	r.TotalPackages = len(requires)

	// Check each require against go.sum.
	covered := 0
	for _, mod := range requires {
		if checksums[mod] {
			covered++
		} else {
			r.Violations = append(r.Violations, Violation{
				Package: mod,
				Type:    "missing_checksum",
				Detail:  "module not found in go.sum",
				Score:   5,
			})
		}
	}

	if r.TotalPackages > 0 {
		r.Coverage = float64(covered) / float64(r.TotalPackages) * 100
	}

	// Check replace directives.
	for _, rep := range replaces {
		if strings.HasPrefix(rep.new, "./") || strings.HasPrefix(rep.new, "../") {
			r.Violations = append(r.Violations, Violation{
				Package: rep.old,
				Type:    "local_replace",
				Detail:  "replace directive points to local path: " + rep.new,
				Score:   6,
			})
		} else if strings.Contains(rep.new, "git") || strings.HasPrefix(rep.new, "https://") {
			r.Violations = append(r.Violations, Violation{
				Package: rep.old,
				Type:    "git_replace",
				Detail:  "replace directive points to git URL: " + rep.new,
				Score:   8,
			})
		}
	}

	r.Score = computeScore(r.Violations)
	return r, nil
}

type replaceDirective struct {
	old string
	new string
}

func parseGoMod(dir string) (requires []string, replaces []replaceDirective, err error) {
	data, readErr := os.ReadFile(filepath.Join(dir, "go.mod"))
	if readErr != nil {
		return nil, nil, readErr
	}

	inRequire := false
	inReplace := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case line == "require (":
			inRequire = true
		case line == "replace (":
			inReplace = true
		case (inRequire || inReplace) && line == ")":
			inRequire = false
			inReplace = false
		case strings.HasPrefix(line, "require "):
			mod := strings.Fields(strings.TrimPrefix(line, "require "))[0]
			requires = append(requires, mod)
		case strings.HasPrefix(line, "replace "):
			r := parseReplaceLine(strings.TrimPrefix(line, "replace "))
			if r.old != "" {
				replaces = append(replaces, r)
			}
		case inRequire && line != "" && !strings.HasPrefix(line, "//"):
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				requires = append(requires, parts[0])
			}
		case inReplace && line != "" && !strings.HasPrefix(line, "//"):
			r := parseReplaceLine(line)
			if r.old != "" {
				replaces = append(replaces, r)
			}
		}
	}
	return requires, replaces, nil
}

// parseReplaceLine parses "old v => new v" or "old => new".
func parseReplaceLine(line string) replaceDirective {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return replaceDirective{}
	}
	// Find "=>" separator.
	for i, p := range parts {
		if p == "=>" && i > 0 && i < len(parts)-1 {
			return replaceDirective{
				old: parts[0],
				new: parts[i+1],
			}
		}
	}
	return replaceDirective{}
}

// parseGoSum returns a set of module paths that have checksums in go.sum.
// go.sum format: "<module> <version> <hash>" (space-separated, not @-separated).
func parseGoSum(dir string) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "go.sum"))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			seen[parts[0]] = true
		}
	}
	return seen, nil
}

// ---------------------------------------------------------------------------
// Node implementation
// ---------------------------------------------------------------------------

func checkNode(dir string) (IntegrityReport, error) {
	// Route to the correct parser based on which lockfile is present.
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err == nil {
		return checkNodePackageLock(dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
		return checkYarnLock(dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "pnpm-lock.yaml")); err == nil {
		return checkPnpmLock(dir)
	}
	return IntegrityReport{}, fmt.Errorf("no supported lockfile found in %s", dir)
}

func checkNodePackageLock(dir string) (IntegrityReport, error) {
	r := IntegrityReport{}

	plPath := filepath.Join(dir, "package-lock.json")
	data, err := os.ReadFile(plPath)
	if err != nil {
		return r, fmt.Errorf("read package-lock.json: %w", err)
	}

	var raw struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
			Resolved  string `json:"resolved"`
			Link      bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
			Resolved  string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return r, fmt.Errorf("parse package-lock.json: %w", err)
	}

	type pkgEntry struct {
		name      string
		integrity string
		resolved  string
	}
	var entries []pkgEntry

	if len(raw.Packages) > 0 {
		for key, pkg := range raw.Packages {
			if key == "" || pkg.Link {
				continue
			}
			name := strings.TrimPrefix(key, "node_modules/")
			if idx := strings.LastIndex(name, "node_modules/"); idx >= 0 {
				name = name[idx+len("node_modules/"):]
			}
			entries = append(entries, pkgEntry{name: name, integrity: pkg.Integrity, resolved: pkg.Resolved})
		}
	} else {
		for name, dep := range raw.Dependencies {
			entries = append(entries, pkgEntry{name: name, integrity: dep.Integrity, resolved: dep.Resolved})
		}
	}

	r.TotalPackages = len(entries)
	covered := 0
	missingIntegrityScore := 0.0

	for _, e := range entries {
		if e.integrity != "" {
			covered++
		} else {
			if missingIntegrityScore < 10 {
				add := 2.0
				if missingIntegrityScore+add > 10 {
					add = 10 - missingIntegrityScore
				}
				r.Violations = append(r.Violations, Violation{
					Package: e.name,
					Type:    "missing_integrity",
					Detail:  "package has no integrity hash",
					Score:   add,
				})
				missingIntegrityScore += add
			}
		}

		if strings.HasPrefix(e.resolved, "file:") {
			r.Violations = append(r.Violations, Violation{
				Package: e.name,
				Type:    "path_dep",
				Detail:  "resolved via file: protocol: " + e.resolved,
				Score:   5,
			})
		} else if strings.HasPrefix(e.resolved, "git+") {
			r.Violations = append(r.Violations, Violation{
				Package: e.name,
				Type:    "git_dep",
				Detail:  "resolved via git+ URL: " + e.resolved,
				Score:   8,
			})
		}
	}

	if r.TotalPackages > 0 {
		r.Coverage = float64(covered) / float64(r.TotalPackages) * 100
	}

	r.Score = computeScore(r.Violations)
	return r, nil
}

// ---------------------------------------------------------------------------
// Yarn implementation (basic: checks for file: and git+ in resolved fields)
// ---------------------------------------------------------------------------

// checkYarnLock scans yarn.lock for path/git dependencies.
// Yarn v1 includes a "resolved" field per package.
func checkYarnLock(dir string) (IntegrityReport, error) {
	r := IntegrityReport{}
	data, err := os.ReadFile(filepath.Join(dir, "yarn.lock"))
	if err != nil {
		return r, fmt.Errorf("read yarn.lock: %w", err)
	}

	var currentName string
	total := 0
	covered := 0

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		// Package declaration (no leading space).
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			decl := strings.TrimSuffix(strings.TrimSpace(line), ":")
			first := strings.Split(decl, ",")[0]
			first = strings.TrimSpace(strings.Trim(first, `"`))
			if idx := strings.LastIndex(first, "@"); idx > 0 {
				currentName = first[:idx]
			} else {
				currentName = first
			}
			total++
			covered++ // yarn doesn't store inline integrity; count as covered
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "resolved ") {
			resolved := strings.Trim(strings.TrimPrefix(trimmed, "resolved "), `"`)
			if strings.HasPrefix(resolved, "file:") {
				r.Violations = append(r.Violations, Violation{
					Package: currentName,
					Type:    "path_dep",
					Detail:  "resolved via file: protocol",
					Score:   5,
				})
			} else if strings.HasPrefix(resolved, "git+") {
				r.Violations = append(r.Violations, Violation{
					Package: currentName,
					Type:    "git_dep",
					Detail:  "resolved via git+ URL",
					Score:   8,
				})
			}
		}
	}

	r.TotalPackages = total
	if total > 0 {
		r.Coverage = float64(covered) / float64(total) * 100
	}
	r.Score = computeScore(r.Violations)
	return r, nil
}

// ---------------------------------------------------------------------------
// pnpm implementation
// ---------------------------------------------------------------------------

// checkPnpmLock scans pnpm-lock.yaml for path/git dependencies.
// pnpm uses a content-addressable store, so integrity is provided by the store
// itself — we report Coverage as N/A (100%) and only flag path/git specifiers.
func checkPnpmLock(dir string) (IntegrityReport, error) {
	r := IntegrityReport{}
	data, err := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
	if err != nil {
		return r, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}

	// Count unique package entries and look for file:/git+ specifiers.
	// We use simple line-based scanning to avoid a YAML dependency.
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// Track current package name from importers section.
	inImporters := false
	currentDep := ""

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "importers:" {
			inImporters = true
			continue
		}
		if inImporters && !strings.HasPrefix(line, " ") && trimmed != "" {
			inImporters = false
		}

		// Count packages section entries: "  pkg@version:" or "  /pkg@version:"
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			if strings.HasSuffix(trimmed, ":") {
				key := strings.TrimSuffix(trimmed, ":")
				key = strings.TrimPrefix(key, "/")
				if key != "" && !seen[key] {
					seen[key] = true
				}
			}
		}

		// Detect dependency name in importers.
		if inImporters && strings.HasPrefix(line, "      ") && strings.HasSuffix(trimmed, ":") {
			currentDep = strings.TrimSuffix(trimmed, ":")
		}

		// specifier: file:... or specifier: git+...
		if strings.HasPrefix(trimmed, "specifier:") {
			spec := strings.TrimSpace(strings.TrimPrefix(trimmed, "specifier:"))
			spec = strings.Trim(spec, `'"`)
			if strings.HasPrefix(spec, "file:") {
				r.Violations = append(r.Violations, Violation{
					Package: currentDep,
					Type:    "path_dep",
					Detail:  "pnpm specifier points to local path: " + spec,
					Score:   5,
				})
			} else if strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "github:") || strings.HasPrefix(spec, "gitlab:") {
				r.Violations = append(r.Violations, Violation{
					Package: currentDep,
					Type:    "git_dep",
					Detail:  "pnpm specifier points to git source: " + spec,
					Score:   8,
				})
			}
		}
	}

	r.TotalPackages = len(seen)
	// pnpm's content-addressable store ensures integrity; report 100% coverage.
	r.Coverage = 100.0
	r.Score = computeScore(r.Violations)
	return r, nil
}

// ---------------------------------------------------------------------------
// Score computation
// ---------------------------------------------------------------------------

func computeScore(violations []Violation) float64 {
	total := 0.0
	for _, v := range violations {
		total += v.Score
	}
	if total > 20 {
		total = 20
	}
	return total
}
