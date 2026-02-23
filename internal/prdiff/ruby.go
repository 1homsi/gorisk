package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// RubyDiffer implements Differ by parsing Gemfile.lock changes.
type RubyDiffer struct{}

func (RubyDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffGemfileLock(baseRef, headRef)
}

// diffGemfileLock diffs Gemfile.lock between two git refs and extracts added,
// removed, and updated gem changes.
func diffGemfileLock(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "Gemfile.lock").Output()
	if err != nil {
		out, err = exec.Command("git", "diff", baseRef, headRef, "--", "Gemfile.lock").Output()
		if err != nil {
			return PRDiffReport{}, fmt.Errorf("git diff Gemfile.lock: %w", err)
		}
	}
	return parseGemfileLockDiff(string(out)), nil
}

// reGemLock matches lines like `    rails (7.0.4)` in the GEM section of
// Gemfile.lock — exactly four leading spaces, gem name, space, version in parens.
var reGemLock = regexp.MustCompile(`^\s{4}(\S+)\s+\(([^)]+)\)`)

// parseGemfileLockDiff parses a unified diff of Gemfile.lock.
func parseGemfileLockDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) < 2 {
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if sign != '+' && sign != '-' {
			continue
		}
		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		if m := reGemLock.FindStringSubmatch(line); m != nil {
			name := m[1]
			ver := m[2]
			if sign == '+' {
				added[name] = ver
			} else {
				removed[name] = ver
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
