package prdiff

import (
	"fmt"
	"os/exec"
	"strings"
)

// DartDiffer implements Differ by parsing pubspec.lock changes.
type DartDiffer struct{}

func (DartDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffPubspecLock(baseRef, headRef)
}

func diffPubspecLock(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "pubspec.lock").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff pubspec.lock: %w", err)
	}
	return parsePubspecLockDiff(string(out)), nil
}

// parsePubspecLockDiff parses a unified diff of pubspec.lock.
//
// pubspec.lock YAML format:
//
//	packages:
//	  http:
//	    dependency: "direct main"
//	    version: "1.2.1"
//
// Strategy: track the current package name from 2-space-indented lines, then
// associate any 4-space-indented `version:` lines with that package.
func parsePubspecLockDiff(diff string) PRDiffReport {
	var report PRDiffReport

	added := make(map[string]string)
	removed := make(map[string]string)

	// Last package name seen on +/- lines per sign.
	addedPkg := ""
	removedPkg := ""

	for _, line := range strings.Split(diff, "\n") {
		if len(line) < 2 {
			continue
		}
		sign := line[0]
		content := line[1:]
		if sign != '+' && sign != '-' {
			// Context line: do not reset package names — indentation context
			// may span context lines. Only reset on blank context lines.
			if strings.TrimSpace(content) == "" {
				addedPkg = ""
				removedPkg = ""
			}
			continue
		}
		if strings.HasPrefix(content, "++") || strings.HasPrefix(content, "--") {
			continue
		}

		indent := countLeadingSpaces(content)
		trimmed := strings.TrimSpace(content)

		switch indent {
		case 2:
			// Package name line: "  pkg_name:" with no value after the colon.
			if strings.HasSuffix(trimmed, ":") {
				pkgName := strings.TrimSuffix(trimmed, ":")
				if sign == '+' {
					addedPkg = pkgName
				} else {
					removedPkg = pkgName
				}
			}
		case 4:
			// Package field lines: look for version.
			key, val, ok := strings.Cut(trimmed, ":")
			if !ok {
				break
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"'`)

			if key == "version" && val != "" {
				if sign == '+' && addedPkg != "" {
					added[addedPkg] = val
				} else if sign == '-' && removedPkg != "" {
					removed[removedPkg] = val
				}
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

// countLeadingSpaces returns the number of leading space characters in s.
func countLeadingSpaces(s string) int {
	count := 0
	for _, ch := range s {
		if ch == ' ' {
			count++
		} else {
			break
		}
	}
	return count
}
