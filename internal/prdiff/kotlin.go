package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// KotlinDiffer implements Differ by parsing Gradle dependency file changes.
type KotlinDiffer struct{}

func (KotlinDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffKotlinGradle(baseRef, headRef)
}

// reKotlinVersion matches lines with a version value in Kotlin/Gradle files.
// Handles libs.versions.toml version entries, build.gradle.kts strings, and build.gradle.
var reKotlinVersionLine = regexp.MustCompile(`"([A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+):([^"]+)"`)

// reTomlVersion matches version assignments in libs.versions.toml.
var reTomlVersion = regexp.MustCompile(`^\s*([A-Za-z0-9._\-]+)\s*=\s*"([0-9][^"]*)"`)

// diffKotlinGradle diffs the Kotlin/Gradle dependency files between two git refs.
// Priority: gradle/libs.versions.toml → build.gradle.kts → build.gradle
func diffKotlinGradle(baseRef, headRef string) (PRDiffReport, error) {
	// Try libs.versions.toml first.
	files := []string{
		"gradle/libs.versions.toml",
		"build.gradle.kts",
		"build.gradle",
	}
	for _, f := range files {
		out, err := exec.Command("git", "diff", baseRef+".."+headRef, "--", f).Output()
		if err != nil {
			continue
		}
		if len(strings.TrimSpace(string(out))) == 0 {
			continue
		}
		if strings.HasSuffix(f, ".toml") {
			return parseKotlinTomlDiff(string(out)), nil
		}
		return parseKotlinGradleDiff(string(out)), nil
	}
	return PRDiffReport{}, fmt.Errorf("no Kotlin/Gradle dependency file changed between %s and %s", baseRef, headRef)
}

// parseKotlinTomlDiff parses a unified diff of libs.versions.toml.
// It looks for lines with module = "group:artifact" and version entries.
func parseKotlinTomlDiff(diff string) PRDiffReport {
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

		// Match "group:artifact:version" pattern.
		if m := reKotlinVersionLine.FindStringSubmatch(content); m != nil {
			pkg := m[1]
			ver := m[2]
			if sign == '+' {
				added[pkg] = ver
			} else {
				removed[pkg] = ver
			}
			continue
		}

		// Match standalone version assignments: key = "1.2.3"
		if strings.Contains(content, "version") {
			if m := reTomlVersion.FindStringSubmatch(content); m != nil {
				key := m[1]
				ver := m[2]
				if sign == '+' {
					added["version:"+key] = ver
				} else {
					removed["version:"+key] = ver
				}
			}
		}
	}

	return buildKotlinReport(added, removed, result)
}

// parseKotlinGradleDiff parses a unified diff of build.gradle.kts or build.gradle.
// Looks for lines like: implementation("group:artifact:version")
func parseKotlinGradleDiff(diff string) PRDiffReport {
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

		if m := reKotlinVersionLine.FindStringSubmatch(content); m != nil {
			pkg := m[1]
			ver := m[2]
			if sign == '+' {
				added[pkg] = ver
			} else {
				removed[pkg] = ver
			}
		}
	}

	return buildKotlinReport(added, removed, result)
}

func buildKotlinReport(added, removed map[string]string, result PRDiffReport) PRDiffReport {
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
