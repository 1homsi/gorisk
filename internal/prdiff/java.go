package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// JavaDiffer implements Differ by parsing pom.xml / build.gradle changes.
type JavaDiffer struct{}

func (JavaDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffJava(baseRef, headRef)
}

// diffJava tries pom.xml first, then build.gradle.
func diffJava(baseRef, headRef string) (PRDiffReport, error) {
	// Try pom.xml first.
	if r, err := diffJavaFile(baseRef, headRef, "pom.xml", parsePomXMLDiff); err == nil && (len(r.Added)+len(r.Updated)+len(r.Removed) > 0) {
		return r, nil
	}

	// Fall back to build.gradle.
	r, err := diffJavaFile(baseRef, headRef, "build.gradle", parseBuildGradleDiff)
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff build.gradle: %w", err)
	}
	return r, nil
}

// diffJavaFile runs git diff on the given file and parses the output.
func diffJavaFile(baseRef, headRef, filename string, parser func(string) PRDiffReport) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", filename).Output()
	if err != nil {
		out, err = exec.Command("git", "diff", baseRef, headRef, "--", filename).Output()
		if err != nil {
			return PRDiffReport{}, fmt.Errorf("git diff %s: %w", filename, err)
		}
	}
	return parser(string(out)), nil
}

var (
	reArtifactID = regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`)
	rePomVersion = regexp.MustCompile(`<version>([^<]+)</version>`)
)

// parsePomXMLDiff parses a unified diff of pom.xml.
// Strategy: track the most recent artifactId seen in the same block and pair
// it with the next version change.
func parsePomXMLDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	var lastArtifact string
	var lastSign byte

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) == 0 {
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if sign != '+' && sign != '-' {
			// Context lines can still carry artifactId — track them without sign.
			if m := reArtifactID.FindStringSubmatch(line); m != nil {
				lastArtifact = strings.TrimSpace(m[1])
				lastSign = ' '
			}
			continue
		}
		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		if m := reArtifactID.FindStringSubmatch(line); m != nil {
			lastArtifact = strings.TrimSpace(m[1])
			lastSign = sign
			continue
		}
		if m := rePomVersion.FindStringSubmatch(line); m != nil && lastArtifact != "" {
			ver := strings.TrimSpace(m[1])
			// Use the sign from the version line; lastSign guides context.
			effectiveSign := sign
			if lastSign == ' ' {
				effectiveSign = sign
			}
			if effectiveSign == '+' {
				added[lastArtifact] = ver
			} else {
				removed[lastArtifact] = ver
			}
		}
	}

	return buildJavaReport(added, removed)
}

// reGradleDepLine matches Gradle dependency declarations:
// `implementation 'group:artifact:version'` or double-quoted variants.
var reGradleDepLine = regexp.MustCompile(`(?:implementation|api|compile|testImplementation|runtimeOnly)\s+['"]([^:'"]+):([^:'"]+):([^:'"]+)['"]`)

// parseBuildGradleDiff parses a unified diff of build.gradle.
func parseBuildGradleDiff(diff string) PRDiffReport {
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

		if m := reGradleDepLine.FindStringSubmatch(line); m != nil {
			groupID := strings.TrimSpace(m[1])
			artifactID := strings.TrimSpace(m[2])
			ver := strings.TrimSpace(m[3])
			name := groupID + "/" + artifactID
			if sign == '+' {
				added[name] = ver
			} else {
				removed[name] = ver
			}
		}
	}

	return buildJavaReport(added, removed)
}

// buildJavaReport converts added/removed maps into a PRDiffReport.
func buildJavaReport(added, removed map[string]string) PRDiffReport {
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
