package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// CppDiffer implements Differ by parsing vcpkg.json or conanfile.txt changes.
type CppDiffer struct{}

func (CppDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffCppManifest(baseRef, headRef)
}

// reVcpkgName matches "name": "value" JSON fields in a diff line.
var reVcpkgName = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

// reVcpkgVersion matches "version": "value" JSON fields in a diff line.
var reVcpkgVersion = regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)

// reConanEntry matches conanfile.txt dependency entries: name/version
var reConanEntry = regexp.MustCompile(`^([A-Za-z0-9_\-.]+)/([^\s@]+)`)

// diffCppManifest diffs vcpkg.json first, then falls back to conanfile.txt.
func diffCppManifest(baseRef, headRef string) (PRDiffReport, error) {
	// Try vcpkg.json first.
	out, err := exec.Command("git", "diff", baseRef+".."+headRef, "--", "vcpkg.json").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return parseVcpkgDiff(string(out)), nil
	}

	// Fall back to conanfile.txt.
	out, err = exec.Command("git", "diff", baseRef+".."+headRef, "--", "conanfile.txt").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff conanfile.txt: %w", err)
	}
	return parseConanfileDiff(string(out)), nil
}

// parseVcpkgDiff parses a unified diff of vcpkg.json.
// Handles both string entries and object entries with "name" and "version" fields.
func parseVcpkgDiff(diff string) PRDiffReport {
	var result PRDiffReport

	addedNames := make(map[string]string)
	removedNames := make(map[string]string)

	// Track current name per sign for multi-line objects.
	var pendingAddName, pendingRemoveName string

	for _, line := range strings.Split(diff, "\n") {
		if len(line) < 2 {
			pendingAddName = ""
			pendingRemoveName = ""
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

		// Check for "name" field.
		if nm := reVcpkgName.FindStringSubmatch(content); nm != nil {
			if sign == '+' {
				pendingAddName = nm[1]
			} else {
				pendingRemoveName = nm[1]
			}
		}

		// Check for "version" field.
		if vm := reVcpkgVersion.FindStringSubmatch(content); vm != nil {
			ver := vm[1]
			if sign == '+' && pendingAddName != "" {
				addedNames[pendingAddName] = ver
			} else if sign == '-' && pendingRemoveName != "" {
				removedNames[pendingRemoveName] = ver
			}
		}

		// Check for simple string dependency entry: "pkgname"
		trimmed := strings.TrimSpace(content)
		if strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(strings.TrimRight(trimmed, ","), `"`) {
			val := strings.Trim(strings.TrimRight(trimmed, ","), `"`)
			if val != "" && !strings.Contains(val, ":") && !strings.Contains(val, "/") {
				if sign == '+' {
					if _, exists := addedNames[val]; !exists {
						addedNames[val] = ""
					}
				} else {
					if _, exists := removedNames[val]; !exists {
						removedNames[val] = ""
					}
				}
			}
		}
	}

	for name, newVer := range addedNames {
		if oldVer, wasPresent := removedNames[name]; wasPresent {
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
	for name := range removedNames {
		if _, stillPresent := addedNames[name]; !stillPresent {
			result.Removed = append(result.Removed, name)
		}
	}

	return result
}

// parseConanfileDiff parses a unified diff of conanfile.txt.
// Dependency lines look like: boost/1.82.0
func parseConanfileDiff(diff string) PRDiffReport {
	var result PRDiffReport

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

		trimmed := strings.TrimSpace(content)
		m := reConanEntry.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name := m[1]
		version := m[2]
		// Strip channel info after @.
		version, _, _ = strings.Cut(version, "@")

		if sign == '+' {
			added[name] = version
		} else {
			removed[name] = version
		}
	}

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
