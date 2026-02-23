package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// JuliaDiffer implements Differ by parsing Manifest.toml changes.
type JuliaDiffer struct{}

func (JuliaDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffJulia(baseRef, headRef)
}

// reJuliaSection matches Julia Manifest.toml section headers of the form:
//
//	[[deps.PackageName]]
var reJuliaSection = regexp.MustCompile(`^\[\[deps\.(\w+)\]\]`)

// reJuliaVersion matches Julia Manifest.toml version lines of the form:
//
//	version = "1.2.3"
var reJuliaVersion = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)

// diffJulia diffs Manifest.toml between two git refs.
func diffJulia(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "Manifest.toml").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff Manifest.toml: %w", err)
	}
	return parseJuliaDiff(string(out)), nil
}

// parseJuliaDiff parses a unified diff of Julia Manifest.toml.
// It tracks the current package section name and sign to associate versions
// with package names across multi-line diff hunks.
func parseJuliaDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	// Track current package context per sign so that section headers and
	// version lines from the same diff side are correlated correctly.
	currentPkgAdded := ""
	currentPkgRemoved := ""

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) < 2 {
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		// Section header — update current package context.
		if m := reJuliaSection.FindStringSubmatch(line); m != nil {
			switch sign {
			case '+':
				currentPkgAdded = m[1]
			case '-':
				currentPkgRemoved = m[1]
			}
			continue
		}

		// Version line — associate with current package context.
		if m := reJuliaVersion.FindStringSubmatch(line); m != nil {
			ver := m[1]
			switch sign {
			case '+':
				if currentPkgAdded != "" {
					added[currentPkgAdded] = ver
				}
			case '-':
				if currentPkgRemoved != "" {
					removed[currentPkgRemoved] = ver
				}
			}
		}
	}

	var r PRDiffReport

	for name, newVer := range added {
		if oldVer, wasPresent := removed[name]; wasPresent {
			r.Updated = append(r.Updated, ModuleDiff{
				Module:     name,
				OldVersion: oldVer,
				NewVersion: newVer,
			})
		} else {
			r.Added = append(r.Added, ModuleDiff{
				Module:     name,
				NewVersion: newVer,
			})
		}
	}
	for name := range removed {
		if _, stillPresent := added[name]; !stillPresent {
			r.Removed = append(r.Removed, name)
		}
	}

	return r
}
