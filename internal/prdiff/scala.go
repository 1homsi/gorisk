package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// ScalaDiffer implements Differ by parsing build.sbt changes.
type ScalaDiffer struct{}

func (ScalaDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffBuildSbt(baseRef, headRef)
}

// reSbtDepDiff matches sbt dependency lines:
// "org.typelevel" %% "cats-core" % "2.9.0"
// "com.typesafe.akka" %% "akka-actor" % "2.8.0"
// group1=org, group2=artifact, group3=version
var reSbtDepDiff = regexp.MustCompile(`"([^"]+)"\s+%%?\s+"([^"]+)"\s+%\s+"([^"]+)"`)

// diffBuildSbt diffs build.sbt between two git refs.
func diffBuildSbt(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+".."+headRef, "--", "build.sbt").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff build.sbt: %w", err)
	}
	return parseBuildSbtDiff(string(out)), nil
}

// parseBuildSbtDiff parses a unified diff of build.sbt and returns
// added/removed/updated package entries.
func parseBuildSbtDiff(diff string) PRDiffReport {
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

		m := reSbtDepDiff.FindStringSubmatch(content)
		if m == nil {
			continue
		}
		org := m[1]
		artifact := m[2]
		version := m[3]
		name := org + "/" + artifact

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
