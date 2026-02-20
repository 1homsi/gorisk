package prdiff

import (
	"fmt"
	"os/exec"
	"strings"
)

// PHPDiffer implements Differ by parsing composer.json / composer.lock changes.
type PHPDiffer struct{}

func (PHPDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffComposerJSON(baseRef, headRef)
}

// diffComposerJSON diffs composer.json between two git refs and extracts
// added, removed, and updated Composer dependency changes.
func diffComposerJSON(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+".."+headRef, "--", "composer.json").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff composer.json: %w", err)
	}
	return parseComposerJSONDiff(string(out)), nil
}

// parseComposerJSONDiff parses a unified diff of composer.json and returns
// added/removed/updated package entries.
func parseComposerJSONDiff(diff string) PRDiffReport {
	var report PRDiffReport

	added := make(map[string]string)
	removed := make(map[string]string)

	for _, line := range strings.Split(diff, "\n") {
		if len(line) < 2 {
			continue
		}
		sign := line[0]
		content := line[1:]
		if sign != '+' && sign != '-' {
			continue
		}
		if strings.HasPrefix(content, "++") || strings.HasPrefix(content, "--") {
			continue
		}

		name, version, ok := parseComposerDepLine(content)
		if !ok {
			continue
		}

		if sign == '+' {
			added[name] = version
		} else {
			removed[name] = version
		}
	}

	for name, newVer := range added {
		if oldVer, wasPresent := removed[name]; wasPresent {
			// Updated
			report.Updated = append(report.Updated, ModuleDiff{
				Module:     name,
				OldVersion: oldVer,
				NewVersion: newVer,
			})
		} else {
			// Newly added
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

// parseComposerDepLine parses a dependency line from a composer.json diff.
// Example: `        "guzzlehttp/guzzle": "^7.0",`
func parseComposerDepLine(line string) (name, version string, ok bool) {
	line = strings.TrimSpace(line)
	// Must start with a quoted string followed by ":"
	if !strings.HasPrefix(line, `"`) {
		return "", "", false
	}
	end := strings.Index(line[1:], `"`)
	if end < 0 {
		return "", "", false
	}
	name = line[1 : end+1]
	// name must look like a Composer package (vendor/package)
	if !strings.Contains(name, "/") {
		return "", "", false
	}
	rest := strings.TrimSpace(line[end+2:])
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimSpace(rest)
	rest = strings.Trim(rest, `",`)
	return name, rest, true
}
