package prdiff

import (
	"fmt"
	"os/exec"
	"strings"
)

// DotnetDiffer implements Differ by parsing packages.lock.json changes.
type DotnetDiffer struct{}

func (DotnetDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffPackagesLockJSON(baseRef, headRef)
}

func diffPackagesLockJSON(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "packages.lock.json").Output()
	if err != nil {
		return PRDiffReport{}, fmt.Errorf("git diff packages.lock.json: %w", err)
	}
	return parsePackagesLockJSONDiff(string(out)), nil
}

// parsePackagesLockJSONDiff parses a unified diff of packages.lock.json.
//
// packages.lock.json format fragment:
//
//	"dependencies": {
//	  ".NETCoreApp,Version=v8.0": {
//	    "Newtonsoft.Json": {
//	      "type": "Direct",
//	      "resolved": "13.0.3",
//	      "contentHash": "..."
//	    }
//	  }
//	}
//
// Strategy: track the last JSON object key seen on +/- lines (these are package
// names when they appear as `"PackageName": {`), then associate any
// `"resolved": "X.Y.Z"` lines with that package name.
func parsePackagesLockJSONDiff(diff string) PRDiffReport {
	var report PRDiffReport

	added := make(map[string]string)
	removed := make(map[string]string)

	addedPkg := ""
	removedPkg := ""

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

		// Detect a package name line: `"PackageName": {`
		if strings.HasSuffix(trimmed, ": {") || strings.HasSuffix(trimmed, ":{") {
			pkgName := extractJSONKey(trimmed)
			if pkgName != "" && looksLikeNuGetPackage(pkgName) {
				if sign == '+' {
					addedPkg = pkgName
				} else {
					removedPkg = pkgName
				}
			}
			continue
		}

		// Detect a resolved version line: `"resolved": "X.Y.Z",`
		if ver, ok := extractJSONStringField(trimmed, "resolved"); ok {
			if sign == '+' && addedPkg != "" {
				added[addedPkg] = ver
			} else if sign == '-' && removedPkg != "" {
				removed[removedPkg] = ver
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

// extractJSONKey extracts the key from a JSON line of the form `"Key": {`.
func extractJSONKey(line string) string {
	if !strings.HasPrefix(line, `"`) {
		return ""
	}
	end := strings.Index(line[1:], `"`)
	if end < 0 {
		return ""
	}
	return line[1 : end+1]
}

// looksLikeNuGetPackage returns true if name looks like a NuGet package name
// (contains a dot or starts with a capital letter — excludes framework
// monikers like ".NETCoreApp,Version=v8.0").
func looksLikeNuGetPackage(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	if strings.Contains(name, ",") {
		return false
	}
	return true
}
