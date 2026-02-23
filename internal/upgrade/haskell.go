package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	haskelladapter "github.com/1homsi/gorisk/internal/adapters/haskell"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

// HaskellUpgrader implements Upgrader for Haskell/Cabal packages.
type HaskellUpgrader struct{}

func (HaskellUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeHaskell(projectDir, pkgName, newVersion)
}

// HaskellCapDiffer implements CapDiffer for Haskell/Cabal packages.
type HaskellCapDiffer struct{}

func (HaskellCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffHaskellCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeHaskell(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := haskellCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	oldCaps := haskellProjectCaps(projectDir)
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// haskellCurrentVersion reads the installed version from cabal.project.freeze or stack.yaml.lock.
func haskellCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := haskelladapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Haskell lockfile", pkgName)
}

// haskellProjectCaps returns capabilities for the Haskell project directory.
func haskellProjectCaps(projectDir string) capability.CapabilitySet {
	if _, err := os.Stat(projectDir); err != nil {
		return capability.CapabilitySet{}
	}
	return haskelladapter.Detect(filepath.Clean(projectDir))
}

func diffHaskellCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}
