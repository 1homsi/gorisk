package prdiff

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// OCamlDiffer implements Differ by parsing *.opam.locked / opam.locked changes.
type OCamlDiffer struct{}

func (OCamlDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffOCaml(baseRef, headRef)
}

// reOpamLocked matches opam.locked dependency entries of the form:
//
//	"package-name" { = "1.2.3" }
var reOpamLocked = regexp.MustCompile(`"([a-zA-Z][a-zA-Z0-9_\-]*)"\s+\{[^}]*=\s+"([0-9][^"]*)"`)

// reOpamPlain matches plain pkgname.version format on diff lines:
//
//	pkgname.1.2.3
var reOpamPlain = regexp.MustCompile(`^([a-z][a-z0-9_\-]+)\.([0-9][0-9.]*)$`)

// diffOCaml diffs *.opam.locked and opam.locked files between two git refs.
func diffOCaml(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command(
		"git", "diff", baseRef+"..."+headRef, "--",
		"*.opam.locked", "opam.locked",
	).Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff ocaml lockfiles: %w", err)
	}
	return parseOCamlDiff(string(out)), nil
}

// parseOCamlDiff parses a unified diff of OCaml opam lockfiles.
func parseOCamlDiff(diff string) PRDiffReport {
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

		// Try the opam locked format first.
		if m := reOpamLocked.FindStringSubmatch(line); m != nil {
			name := m[1]
			ver := strings.TrimSpace(m[2])
			if sign == '+' {
				added[name] = ver
			} else {
				removed[name] = ver
			}
			continue
		}

		// Try the plain pkgname.version format.
		trimmed := strings.TrimSpace(line)
		if m := reOpamPlain.FindStringSubmatch(trimmed); m != nil {
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
