package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

func analyzeNode(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := nodeCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the currently installed package in node_modules.
	oldCaps := nodeModuleCaps(projectDir, pkgName)

	// New capabilities: download from npm registry and scan.
	newDir, err := nodeadapter.DownloadPackage(pkgName, newVersion)
	if err != nil {
		return r, fmt.Errorf("download %s@%s: %w", pkgName, newVersion, err)
	}
	defer os.RemoveAll(newDir)

	newCaps := nodeadapter.Detect(newDir)

	// Compare direct dependencies declared in package.json.
	oldDeps := nodePackageDeps(filepath.Join(projectDir, "node_modules", pkgName))
	newDeps := nodePackageDeps(newDir)
	for dep := range newDeps {
		if _, existed := oldDeps[dep]; !existed {
			r.NewDeps = append(r.NewDeps, dep)
		}
	}

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	} else if len(r.NewDeps) > 0 {
		r.Risk = "MEDIUM"
	}

	return r, nil
}

// nodeCurrentVersion reads the installed version of pkgName from node_modules.
func nodeCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgJSON := filepath.Join(projectDir, "node_modules", pkgName, "package.json")
	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		return "", fmt.Errorf("read node_modules/%s/package.json: %w", pkgName, err)
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", err
	}
	return meta.Version, nil
}

// nodeModuleCaps returns capabilities for the installed version of pkgName.
func nodeModuleCaps(projectDir, pkgName string) capability.CapabilitySet {
	dir := filepath.Join(projectDir, "node_modules", pkgName)
	if _, err := os.Stat(dir); err != nil {
		return capability.CapabilitySet{}
	}
	return nodeadapter.Detect(dir)
}

// nodePackageDeps reads the "dependencies" field from a package.json in dir.
func nodePackageDeps(dir string) map[string]string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var meta struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}
	return meta.Dependencies
}

// capEscalated returns true if newCaps introduces any high-severity capability
// not present in oldCaps.
func capEscalated(old, new capability.CapabilitySet) bool {
	for _, c := range []capability.Capability{
		capability.CapExec, capability.CapNetwork, capability.CapUnsafe, capability.CapPlugin,
	} {
		if new.Has(c) && !old.Has(c) {
			return true
		}
	}
	return false
}
