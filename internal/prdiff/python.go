package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// PythonDiffer implements Differ by parsing poetry.lock / Pipfile.lock /
// requirements.txt changes.
type PythonDiffer struct{}

func (PythonDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffPython(baseRef, headRef)
}

// diffPython tries poetry.lock, then Pipfile.lock, then requirements.txt.
func diffPython(baseRef, headRef string) (PRDiffReport, error) {
	// Try poetry.lock first.
	if r, err := diffPythonFile(baseRef, headRef, "poetry.lock", parsePoetrylockDiff); err == nil && (len(r.Added)+len(r.Updated)+len(r.Removed) > 0) {
		return r, nil
	}

	// Try Pipfile.lock second.
	if r, err := diffPythonFile(baseRef, headRef, "Pipfile.lock", parsePipfilelockDiff); err == nil && (len(r.Added)+len(r.Updated)+len(r.Removed) > 0) {
		return r, nil
	}

	// Fall back to requirements.txt.
	r, err := diffPythonFile(baseRef, headRef, "requirements.txt", parseRequirementsDiff)
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff requirements.txt: %w", err)
	}
	return r, nil
}

// diffPythonFile runs git diff on the given file and parses the output.
func diffPythonFile(baseRef, headRef, filename string, parser func(string) PRDiffReport) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", filename).Output()
	if err != nil {
		// Fallback: try two-dot diff.
		out, err = exec.Command("git", "diff", baseRef, headRef, "--", filename).Output()
		if err != nil {
			return PRDiffReport{}, fmt.Errorf("git diff %s: %w", filename, err)
		}
	}
	return parser(string(out)), nil
}

// rePoetryName matches `name = "requests"` in poetry.lock diff lines.
var rePoetryName = regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"`)

// rePoetryVersion matches `version = "2.28.0"` in poetry.lock diff lines.
var rePoetryVersion = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)

// parsePoetrylockDiff parses a unified diff of poetry.lock.
func parsePoetrylockDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	var pendingName string
	var pendingSign byte

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) == 0 {
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if sign != '+' && sign != '-' {
			// Context line — reset pending state.
			pendingName = ""
			pendingSign = 0
			continue
		}
		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		if m := rePoetryName.FindStringSubmatch(line); m != nil {
			pendingName = m[1]
			pendingSign = sign
			continue
		}
		if m := rePoetryVersion.FindStringSubmatch(line); m != nil && pendingName != "" && pendingSign == sign {
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

	return buildReport(added, removed)
}

// parsePipfilelockDiff parses a unified diff of Pipfile.lock (JSON format).
// We look for lines like: `        "version": "==2.28.0"` preceded by a
// package name key.
func parsePipfilelockDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	rePipName := regexp.MustCompile(`^\s*"([a-zA-Z0-9_.\-]+)"\s*:\s*\{`)
	rePipVer := regexp.MustCompile(`^\s*"version"\s*:\s*"[=><^~]*([^"]+)"`)

	var pendingName string
	var pendingSign byte

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) == 0 {
			continue
		}
		sign := rawLine[0]
		line := rawLine[1:]

		if sign != '+' && sign != '-' {
			pendingName = ""
			pendingSign = 0
			continue
		}
		if strings.HasPrefix(line, "++") || strings.HasPrefix(line, "--") {
			continue
		}

		if m := rePipName.FindStringSubmatch(line); m != nil {
			pendingName = m[1]
			pendingSign = sign
			continue
		}
		if m := rePipVer.FindStringSubmatch(line); m != nil && pendingName != "" && pendingSign == sign {
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

	return buildReport(added, removed)
}

// reReqLine matches `requests==2.28.0` or `requests>=2.28.0` etc.
var reReqLine = regexp.MustCompile(`^([a-zA-Z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s,;#]+)`)

// parseRequirementsDiff parses a unified diff of requirements.txt.
func parseRequirementsDiff(diff string) PRDiffReport {
	added := make(map[string]string)
	removed := make(map[string]string)

	for _, rawLine := range strings.Split(diff, "\n") {
		if len(rawLine) < 2 {
			continue
		}
		sign := rawLine[0]
		line := strings.TrimSpace(rawLine[1:])

		if sign != '+' && sign != '-' {
			continue
		}
		if strings.HasPrefix(rawLine[1:], "++") || strings.HasPrefix(rawLine[1:], "--") {
			continue
		}

		if m := reReqLine.FindStringSubmatch(line); m != nil {
			name := strings.ToLower(m[1])
			ver := m[2]
			if sign == '+' {
				added[name] = ver
			} else {
				removed[name] = ver
			}
		}
	}

	return buildReport(added, removed)
}

// buildReport converts added/removed maps into a PRDiffReport.
func buildReport(added, removed map[string]string) PRDiffReport {
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
