package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// RustDiffer implements Differ by parsing Cargo.lock changes.
type RustDiffer struct{}

func (RustDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffCargoLock(baseRef, headRef)
}

// diffCargoLock diffs Cargo.lock between two git refs and extracts added,
// removed, and updated crate changes.
func diffCargoLock(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "Cargo.lock").Output()
	if err != nil {
		out, err = exec.Command("git", "diff", baseRef, headRef, "--", "Cargo.lock").Output()
		if err != nil {
			return PRDiffReport{}, fmt.Errorf("git diff Cargo.lock: %w", err)
		}
	}
	return parseCargoLockDiff(string(out)), nil
}

var (
	reCargoName    = regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"`)
	reCargoVersion = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)
)

// parseCargoLockDiff parses a unified diff of Cargo.lock.
// Cargo.lock uses TOML [[package]] blocks; name and version appear in sequence.
func parseCargoLockDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	var pendingName string
	var pendingSign byte

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) == 0 {
			pendingName = ""
			pendingSign = 0
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if sign != '+' && sign != '-' {
			// Context lines may reset block boundaries.
			if strings.TrimSpace(line) == "[[package]]" {
				pendingName = ""
				pendingSign = 0
			}
			continue
		}
		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		if m := reCargoName.FindStringSubmatch(line); m != nil {
			pendingName = m[1]
			pendingSign = sign
			continue
		}
		if m := reCargoVersion.FindStringSubmatch(line); m != nil && pendingName != "" && pendingSign == sign {
			ver := m[1]
			if sign == '+' {
				added[pendingName] = ver
			} else {
				removed[pendingName] = ver
			}
			pendingName = ""
			pendingSign = 0
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
