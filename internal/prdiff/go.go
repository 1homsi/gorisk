package prdiff

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"

	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

func diffGoMod(baseRef, headRef string) (PRDiffReport, error) {
	out, err := exec.Command("git", "diff", baseRef+"..."+headRef, "--", "go.mod").Output()
	if err != nil {
		out, err = exec.Command("git", "diff", baseRef, headRef, "--", "go.mod").Output()
		if err != nil {
			return PRDiffReport{}, err
		}
	}

	added := make(map[string]string)
	removed := make(map[string]string)

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		prefix := line[0]
		rest := strings.TrimSpace(line[1:])
		if prefix != '+' && prefix != '-' {
			continue
		}
		if !strings.HasPrefix(rest, "require ") && !strings.HasPrefix(rest, "\t") {
			continue
		}
		rest = strings.TrimPrefix(rest, "require ")
		rest = strings.TrimPrefix(rest, "\t")
		rest = strings.TrimSuffix(rest, " // indirect")
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			continue
		}
		modPath := fields[0]
		version := fields[1]
		if prefix == '+' {
			added[modPath] = version
		} else {
			removed[modPath] = version
		}
	}

	var report PRDiffReport

	for modPath, newVer := range added {
		if oldVer, wasPresent := removed[modPath]; wasPresent {
			caps := goScanModuleCaps(modPath, newVer)
			oldCaps := goScanModuleCaps(modPath, oldVer)
			escalated := caps.Score > oldCaps.Score
			report.Updated = append(report.Updated, ModuleDiff{
				Module:       modPath,
				OldVersion:   oldVer,
				NewVersion:   newVer,
				Caps:         caps,
				CapEscalated: escalated,
			})
		} else {
			caps := goScanModuleCaps(modPath, newVer)
			report.Added = append(report.Added, ModuleDiff{
				Module:     modPath,
				NewVersion: newVer,
				Caps:       caps,
			})
		}
	}

	for modPath := range removed {
		if _, nowPresent := added[modPath]; !nowPresent {
			report.Removed = append(report.Removed, modPath)
		}
	}

	return report, nil
}

func goScanModuleCaps(modulePath, version string) capability.CapabilitySet {
	tmpDir := goFetchModuleSource(modulePath, version)
	if tmpDir == "" {
		return capability.CapabilitySet{}
	}

	g, err := graph.Load(tmpDir)
	if err != nil {
		return capability.CapabilitySet{}
	}

	var combined capability.CapabilitySet
	for _, pkg := range g.Packages {
		if pkg.Module != nil && pkg.Module.Path == modulePath {
			// Populate capabilities since graph.Load no longer does it.
			caps, err := goadapter.DetectPackage(pkg.Dir, pkg.GoFiles)
			if err == nil {
				combined.Merge(caps)
			}
		}
	}
	return combined
}

func goFetchModuleSource(modulePath, version string) string {
	modSpec := modulePath
	if version != "" {
		modSpec = modulePath + "@" + version
	}

	out, err := exec.Command("go", "list", "-m", "-json", modSpec).Output()
	if err != nil {
		return ""
	}

	var result struct {
		Dir string `json:"Dir"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return ""
	}
	return result.Dir
}
