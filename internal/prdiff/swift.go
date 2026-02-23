package prdiff

import (
	"fmt"
	"os/exec"
	"strings"
)

// SwiftDiffer implements Differ by parsing Package.resolved changes.
type SwiftDiffer struct{}

func (SwiftDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffPackageResolved(baseRef, headRef)
}

func diffPackageResolved(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "Package.resolved").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff Package.resolved: %w", err)
	}
	return parsePackageResolvedDiff(string(out)), nil
}

// parsePackageResolvedDiff parses a unified diff of Package.resolved and
// returns added/removed/updated Swift Package Manager dependencies.
//
// Package.resolved v2 JSON fragment (each pin):
//
//	{
//	  "identity" : "vapor",
//	  "kind" : "remoteSourceControl",
//	  "location" : "https://github.com/vapor/vapor.git",
//	  "state" : {
//	    "revision" : "abc123",
//	    "version" : "4.74.0"
//	  }
//	}
func parsePackageResolvedDiff(diff string) PRDiffReport {
	var report PRDiffReport

	// Track the last seen identity per sign so we can pair it with a version.
	addedIdentity := ""
	removedIdentity := ""

	added := make(map[string]string)
	removed := make(map[string]string)

	for _, line := range strings.Split(diff, "\n") {
		if len(line) < 2 {
			continue
		}
		sign := line[0]
		content := line[1:]
		if sign != '+' && sign != '-' {
			// Context line: reset pending identities so they don't bleed across hunks.
			addedIdentity = ""
			removedIdentity = ""
			continue
		}
		if strings.HasPrefix(content, "++") || strings.HasPrefix(content, "--") {
			continue
		}

		trimmed := strings.TrimSpace(content)

		// Match "identity" : "name" lines.
		if id, ok := extractJSONStringField(trimmed, "identity"); ok {
			if sign == '+' {
				addedIdentity = id
			} else {
				removedIdentity = id
			}
			continue
		}

		// Match "version" : "X.Y.Z" lines.
		if ver, ok := extractJSONStringField(trimmed, "version"); ok {
			if sign == '+' && addedIdentity != "" {
				added[addedIdentity] = ver
				addedIdentity = ""
			} else if sign == '-' && removedIdentity != "" {
				removed[removedIdentity] = ver
				removedIdentity = ""
			}
		}
	}

	for name, newVer := range added {
		if oldVer, wasPresent := removed[name]; wasPresent {
			report.Updated = append(report.Updated, ModuleDiff{
				Module:     name,
				OldVersion: oldVer,
				NewVersion: newVer,
			})
		} else {
			report.Added = append(report.Added, ModuleDiff{
				Module:     name,
				NewVersion: newVer,
			})
		}
	}
	for name := range removed {
		if _, stillPresent := added[name]; !stillPresent {
			report.Removed = append(report.Removed, name)
		}
	}

	return report
}

// extractJSONStringField extracts the value from a JSON key-value line of the form:
// `"key" : "value"` or `"key": "value"`.
func extractJSONStringField(line, key string) (value string, ok bool) {
	needle := `"` + key + `"`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return "", false
	}
	rest := line[idx+len(needle):]
	// Skip optional whitespace and colon.
	rest = strings.TrimLeft(rest, " \t:")
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, `"`) {
		return "", false
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}
