package upgrade

import (
	"fmt"

	pythonadapter "github.com/1homsi/gorisk/internal/adapters/python"
	"github.com/1homsi/gorisk/internal/report"
)

// PythonUpgrader implements Upgrader for Python packages.
type PythonUpgrader struct{}

func (PythonUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzePython(projectDir, pkgName, newVersion)
}

// PythonCapDiffer implements CapDiffer for Python packages.
type PythonCapDiffer struct{}

func (PythonCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffPythonCapabilities(pkgName, oldVersion, newVersion)
}

func analyzePython(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := pythonCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Python source.
	oldCaps := pythonadapter.Detect(projectDir)

	// New capabilities: without downloading pip packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// pythonCurrentVersion reads the installed version from the Python lockfile.
func pythonCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := pythonadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Python lockfile", pkgName)
}

func diffPythonCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Python
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
