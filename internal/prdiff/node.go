package prdiff

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	"github.com/1homsi/gorisk/internal/capability"
)

// diffPackageJSON diffs package.json / lockfile changes between baseRef and
// headRef to produce a PRDiffReport for a Node.js project.
func diffPackageJSON(baseRef, headRef string) (PRDiffReport, error) {
	added, removed, err := parseLockfileDiff(baseRef, headRef)
	if err != nil {
		return PRDiffReport{}, err
	}

	var report PRDiffReport

	for pkgName, newVer := range added {
		if oldVer, wasPresent := removed[pkgName]; wasPresent {
			newCaps := npmPackageCaps(pkgName, newVer)
			oldCaps := npmPackageCaps(pkgName, oldVer)
			report.Updated = append(report.Updated, ModuleDiff{
				Module:       pkgName,
				OldVersion:   oldVer,
				NewVersion:   newVer,
				Caps:         newCaps,
				CapEscalated: newCaps.Score > oldCaps.Score,
			})
		} else {
			caps := npmPackageCaps(pkgName, newVer)
			report.Added = append(report.Added, ModuleDiff{
				Module:     pkgName,
				NewVersion: newVer,
				Caps:       caps,
			})
		}
	}

	for pkgName := range removed {
		if _, nowPresent := added[pkgName]; !nowPresent {
			report.Removed = append(report.Removed, pkgName)
		}
	}

	return report, nil
}

// parseLockfileDiff diffs package.json and common lockfiles to find
// added and removed npm packages between the two refs.
func parseLockfileDiff(baseRef, headRef string) (added, removed map[string]string, err error) {
	added = make(map[string]string)
	removed = make(map[string]string)

	lockfiles := []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	args := append([]string{"diff", baseRef + "..." + headRef, "--"}, lockfiles...)
	out, diffErr := exec.Command("git", args...).Output()
	if diffErr != nil {
		args = append([]string{"diff", baseRef, headRef, "--"}, lockfiles...)
		out, diffErr = exec.Command("git", args...).Output()
		if diffErr != nil {
			return nil, nil, diffErr
		}
	}

	// Parse the package.json section of the diff for dependency changes.
	inPackageJSON := false
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "diff --git") {
			inPackageJSON = strings.HasSuffix(line, "package.json")
			continue
		}
		if !inPackageJSON || len(line) < 2 {
			continue
		}

		prefix := line[0]
		if prefix != '+' && prefix != '-' {
			continue
		}
		rest := strings.TrimSpace(line[1:])

		name, ver, ok := parsePackageJSONDepLine(rest)
		if !ok {
			continue
		}

		if prefix == '+' {
			added[name] = ver
		} else {
			removed[name] = ver
		}
	}

	return added, removed, nil
}

// parsePackageJSONDepLine parses a JSON property line like:
//
//	"lodash": "^4.17.21",
func parsePackageJSONDepLine(line string) (name, version string, ok bool) {
	line = strings.TrimSuffix(strings.TrimSpace(line), ",")
	var m map[string]string
	if err := json.Unmarshal([]byte("{"+line+"}"), &m); err != nil {
		return "", "", false
	}
	for k, v := range m {
		return k, strings.TrimLeft(v, "^~>=<"), true
	}
	return "", "", false
}

// npmPackageCaps downloads pkgName@version from npm and returns its capability set.
// Returns an empty set on any error (best-effort).
func npmPackageCaps(pkgName, version string) capability.CapabilitySet {
	version = strings.TrimLeft(version, "^~>=< ")
	if version == "" || version == "*" {
		return capability.CapabilitySet{}
	}

	tmpDir, err := nodeadapter.DownloadPackage(pkgName, version)
	if err != nil {
		return capability.CapabilitySet{}
	}
	defer os.RemoveAll(tmpDir)

	return nodeadapter.Detect(tmpDir)
}
