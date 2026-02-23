package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// PerlDiffer implements Differ by parsing cpanfile.snapshot changes.
type PerlDiffer struct{}

func (PerlDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffPerl(baseRef, headRef)
}

// rePerlModule matches module name + version lines in cpanfile.snapshot of the form:
//
//	Module::Name 1.2.3
var rePerlModule = regexp.MustCompile(`^\s+([A-Z][A-Za-z0-9:]+)\s+([0-9][0-9.]*)`)

// diffPerl diffs cpanfile.snapshot between two git refs.
func diffPerl(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "cpanfile.snapshot").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff cpanfile.snapshot: %w", err)
	}
	return parsePerlDiff(string(out)), nil
}

// parsePerlDiff parses a unified diff of cpanfile.snapshot.
func parsePerlDiff(diff string) PRDiffReport {
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

		if m := rePerlModule.FindStringSubmatch(line); m != nil {
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
