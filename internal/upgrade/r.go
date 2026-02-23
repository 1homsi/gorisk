package upgrade

import (
	"fmt"

	radapter "github.com/1homsi/gorisk/internal/adapters/r"
	"github.com/1homsi/gorisk/internal/report"
)

// RUpgrader implements Upgrader for R packages.
type RUpgrader struct{}

func (RUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeR(projectDir, pkgName, newVersion)
}

// RCapDiffer implements CapDiffer for R packages.
type RCapDiffer struct{}

func (RCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffRCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeR(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := rCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for R source.
	oldCaps := radapter.Detect(projectDir)

	// New capabilities: without downloading CRAN packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// rCurrentVersion reads the installed version from renv.lock.
func rCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := radapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in R dependency file", pkgName)
}

func diffRCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary R
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
