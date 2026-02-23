package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// ClojureDiffer implements Differ by parsing deps.edn / project.clj changes.
type ClojureDiffer struct{}

func (ClojureDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffClojure(baseRef, headRef)
}

// reDepsEdn matches deps.edn dependency lines of the form:
//
//	org.clojure/clojure {:mvn/version "1.11.1"}
var reDepsEdn = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9._\-]*/[a-zA-Z][a-zA-Z0-9._\-]*)\s+\{:mvn/version\s+"([^"]+)"`)

// reProjectClj matches project.clj dependency vectors of the form:
//
//	[org.clojure/clojure "1.11.1"]
var reProjectClj = regexp.MustCompile(`\[([a-zA-Z][^\s]+)\s+"([0-9][^"]+)"\]`)

// diffClojure diffs deps.edn first, then project.clj between two git refs.
func diffClojure(baseRef, headRef string) (PRDiffReport, error) {
	// Try deps.edn first.
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "deps.edn").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return parseClojureDiff(string(out), reDepsEdn), nil
	}

	// Fall back to project.clj.
	out, err = exec.Command("git", "diff", baseRef+"..."+headRef, "--", "project.clj").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff clojure files: %w", err)
	}
	return parseClojureDiff(string(out), reProjectClj), nil
}

// parseClojureDiff parses a unified diff of a Clojure dependency file using
// the provided regex. The regex must capture (name, version) as groups 1 and 2.
func parseClojureDiff(diff string, re *regexp.Regexp) PRDiffReport {
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

		if m := re.FindStringSubmatch(line); m != nil {
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
