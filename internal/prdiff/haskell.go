package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// HaskellDiffer implements Differ by parsing cabal.project.freeze or stack.yaml.lock changes.
type HaskellDiffer struct{}

func (HaskellDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffHaskellLockfile(baseRef, headRef)
}

// reCabalFreeze matches cabal.project.freeze constraint lines:
// constraints: pkg ==version,
var reCabalFreeze = regexp.MustCompile(`([a-z][a-z0-9-]*)\s*==\s*([0-9][0-9.]*)`)

// reStackLock matches stack.yaml.lock hackage entries:
// hackage: pkg-version@sha...
var reStackLock = regexp.MustCompile(`hackage:\s+([a-z][a-z0-9-]*)-([0-9][0-9.]*)@`)

// diffHaskellLockfile diffs cabal.project.freeze first, then falls back to stack.yaml.lock.
func diffHaskellLockfile(baseRef, headRef string) (PRDiffReport, error) {
	// Try cabal.project.freeze first.
	out, err := exec.Command("git", "diff", baseRef+".."+headRef, "--", "cabal.project.freeze").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return parseCabalFreezeDiff(string(out)), nil
	}

	// Fall back to stack.yaml.lock.
	out, err = exec.Command("git", "diff", baseRef+".."+headRef, "--", "stack.yaml.lock").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff stack.yaml.lock: %w", err)
	}
	return parseStackLockDiff(string(out)), nil
}

// parseCabalFreezeDiff parses a unified diff of cabal.project.freeze.
func parseCabalFreezeDiff(diff string) PRDiffReport {
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

		m := reCabalFreeze.FindStringSubmatch(content)
		if m == nil {
			continue
		}
		name := m[1]
		version := m[2]

		if sign == '+' {
			added[name] = version
		} else {
			removed[name] = version
		}
	}

	return buildHaskellReport(added, removed)
}

// parseStackLockDiff parses a unified diff of stack.yaml.lock.
func parseStackLockDiff(diff string) PRDiffReport {
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

		m := reStackLock.FindStringSubmatch(content)
		if m == nil {
			continue
		}
		name := m[1]
		version := m[2]

		if sign == '+' {
			added[name] = version
		} else {
			removed[name] = version
		}
	}

	return buildHaskellReport(added, removed)
}

func buildHaskellReport(added, removed map[string]string) PRDiffReport {
	var result PRDiffReport

	for name, newVer := range added {
		if oldVer, wasPresent := removed[name]; wasPresent {
			result.Updated = append(result.Updated, ModuleDiff{
				Module:     name,
				OldVersion: oldVer,
				NewVersion: newVer,
			})
		} else {
			result.Added = append(result.Added, ModuleDiff{
				Module:     name,
				NewVersion: newVer,
			})
		}
	}
	for name := range removed {
		if _, stillPresent := added[name]; !stillPresent {
			result.Removed = append(result.Removed, name)
		}
	}

	return result
}
