package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// ElixirDiffer implements Differ by parsing mix.lock changes.
type ElixirDiffer struct{}

func (ElixirDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffMixLock(baseRef, headRef)
}

// reMixLockEntry matches a mix.lock dependency entry line.
// mix.lock format: "package": {:hex, :package_name, "1.2.3", ...}
// Group 1 = package name (atom), group 2 = version string.
var reMixLockEntry = regexp.MustCompile(`:(\w+),\s+"([^"]+)"`)

func diffMixLock(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "mix.lock").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff mix.lock: %w", err)
	}
	return parseMixLockDiff(string(out)), nil
}

func parseMixLockDiff(diff string) PRDiffReport {
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

		// Extract the outer quoted package key first: "package_name": ...
		name, version, ok := parseMixLockLine(content)
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

// parseMixLockLine extracts the package name and version from a mix.lock diff line.
// Example: `  "bcrypt_elixir": {:hex, :bcrypt_elixir, "3.0.1", ...},`
// Returns name = "bcrypt_elixir", version = "3.0.1".
func parseMixLockLine(line string) (name, version string, ok bool) {
	trimmed := strings.TrimSpace(line)

	// The outer package key is a quoted string before the colon.
	if !strings.HasPrefix(trimmed, `"`) {
		return "", "", false
	}
	end := strings.Index(trimmed[1:], `"`)
	if end < 0 {
		return "", "", false
	}
	name = trimmed[1 : end+1]
	if name == "" {
		return "", "", false
	}

	// Use regex to find :atom, "version" inside the value tuple.
	m := reMixLockEntry.FindStringSubmatch(trimmed)
	if m == nil {
		return "", "", false
	}
	version = m[2]
	return name, version, true
}
