package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// RDiffer implements Differ by parsing renv.lock changes.
type RDiffer struct{}

func (RDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffR(baseRef, headRef)
}

// reRPackage matches "Package": "pkgname" JSON fields in renv.lock.
var reRPackage = regexp.MustCompile(`"Package"\s*:\s*"([^"]+)"`)

// reRVersion matches "Version": "1.2.3" JSON fields in renv.lock.
var reRVersion = regexp.MustCompile(`"Version"\s*:\s*"([^"]+)"`)

// diffR diffs renv.lock between two git refs.
func diffR(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "renv.lock").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff renv.lock: %w", err)
	}
	return parseRDiff(string(out)), nil
}

// parseRDiff parses a unified diff of renv.lock (JSON format).
// It tracks Package and Version fields on the same diff sign to pair them.
func parseRDiff(diff string) PRDiffReport {
	// Per-sign tracking: accumulate package names and versions seen together.
	addedPkgs := make(map[string]string)
	removedPkgs := make(map[string]string)

	pendingName := map[byte]string{'+': "", '-': ""}

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

		if m := reRPackage.FindStringSubmatch(line); m != nil {
			pendingName[sign] = m[1]
			continue
		}

		if m := reRVersion.FindStringSubmatch(line); m != nil {
			ver := m[1]
			name := pendingName[sign]
			if name == "" {
				continue
			}
			switch sign {
			case '+':
				addedPkgs[name] = ver
			case '-':
				removedPkgs[name] = ver
			}
			pendingName[sign] = ""
		}
	}

	var r PRDiffReport

	for name, newVer := range addedPkgs {
		if oldVer, wasPresent := removedPkgs[name]; wasPresent {
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
	for name := range removedPkgs {
		if _, stillPresent := addedPkgs[name]; !stillPresent {
			r.Removed = append(r.Removed, name)
		}
	}

	return r
}
