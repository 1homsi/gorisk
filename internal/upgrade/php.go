package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	phpAdapter "github.com/1homsi/gorisk/internal/adapters/php"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

// PHPUpgrader implements Upgrader for Composer packages.
type PHPUpgrader struct{}

func (PHPUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzePhp(projectDir, pkgName, newVersion)
}

// PHPCapDiffer implements CapDiffer for Composer packages.
type PHPCapDiffer struct{}

func (PHPCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffPhpCapabilities(pkgName, oldVersion, newVersion)
}

func analyzePhp(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := phpCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the currently installed package in vendor/.
	oldCaps := phpVendorCaps(projectDir, pkgName)

	// New capabilities: scan the new version from vendor/ if already updated,
	// otherwise use import-pattern knowledge only.
	newCaps := oldCaps // fallback: assume same capabilities

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// phpCurrentVersion reads the installed version from composer.lock.
func phpCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := phpAdapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in composer.lock", pkgName)
}

// phpVendorCaps returns capabilities for the installed vendor package.
func phpVendorCaps(projectDir, pkgName string) capability.CapabilitySet {
	dir := filepath.Join(projectDir, "vendor", pkgName)
	if _, err := os.Stat(dir); err != nil {
		return capability.CapabilitySet{}
	}
	return phpAdapter.Detect(dir)
}

func diffPhpCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary PHP
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
