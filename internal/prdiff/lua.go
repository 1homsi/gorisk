package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// LuaDiffer implements Differ by parsing luarocks.lock changes.
type LuaDiffer struct{}

func (LuaDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffLua(baseRef, headRef)
}

// reLuaVersion matches version lines in luarocks.lock of the form:
//
//	version: "3.0rc1-2"
//	version: 3.0rc1-2
var reLuaVersion = regexp.MustCompile(`version:\s*"?([0-9][^"\s]*)"?`)

// reLuaPkgKey matches an unindented (or single-indent) package key line in
// luarocks.lock YAML-like format:
//
//	luasocket:
var reLuaPkgKey = regexp.MustCompile(`^  ([a-zA-Z][a-zA-Z0-9_\-]*):\s*$`)

// diffLua diffs luarocks.lock between two git refs.
func diffLua(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "luarocks.lock").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff luarocks.lock: %w", err)
	}
	return parseLuaDiff(string(out)), nil
}

// parseLuaDiff parses a unified diff of luarocks.lock.
// It tracks the current package key from unindented lines and collects
// version values from version: lines under each key.
func parseLuaDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	currentPkgAdded := ""
	currentPkgRemoved := ""

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) < 2 {
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		// Check for package key line.
		if m := reLuaPkgKey.FindStringSubmatch(line); m != nil {
			switch sign {
			case '+':
				currentPkgAdded = m[1]
			case '-':
				currentPkgRemoved = m[1]
			}
			continue
		}

		// Check for version line.
		if m := reLuaVersion.FindStringSubmatch(line); m != nil {
			ver := m[1]
			switch sign {
			case '+':
				if currentPkgAdded != "" {
					added[currentPkgAdded] = ver
				}
			case '-':
				if currentPkgRemoved != "" {
					removed[currentPkgRemoved] = ver
				}
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
