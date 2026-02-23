package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// ErlangDiffer implements Differ by parsing rebar.lock / rebar.config changes.
type ErlangDiffer struct{}

func (ErlangDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffErlang(baseRef, headRef)
}

// reRebarLock matches rebar.lock entries of the form:
//
//	{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.9.0">>,...},0}.
var reRebarLock = regexp.MustCompile(`\{<<"([^"]+)">>,\{pkg,<<"[^"]*">>,<<"([^"]+)">>`)

// diffErlang diffs rebar.lock first, then rebar.config between two git refs.
func diffErlang(baseRef, headRef string) (PRDiffReport, error) {
	// Try rebar.lock first.
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "rebar.lock").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return parseErlangDiff(string(out), reRebarLock), nil
	}

	// Fall back to rebar.config.
	out, err = exec.Command("git", "diff", baseRef+"..."+headRef, "--", "rebar.config").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff erlang files: %w", err)
	}
	return parseErlangRebarConfig(string(out)), nil
}

// reRebarConfig matches rebar.config dependency entries of the form:
//
//	{cowboy, "2.9.0"}
var reRebarConfig = regexp.MustCompile(`\{(\w+)\s*,\s*"([^"]+)"\s*\}`)

// parseErlangRebarConfig parses rebar.config diff lines.
func parseErlangRebarConfig(diff string) PRDiffReport {
	return parseErlangDiff(diff, reRebarConfig)
}

// parseErlangDiff parses a unified diff of an Erlang dependency file using
// the provided regex. The regex must capture (name, version) as groups 1 and 2.
func parseErlangDiff(diff string, re *regexp.Regexp) PRDiffReport {
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
