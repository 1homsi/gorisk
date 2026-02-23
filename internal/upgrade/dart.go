package upgrade

import (
	"fmt"

	dartadapter "github.com/1homsi/gorisk/internal/adapters/dart"
	"github.com/1homsi/gorisk/internal/report"
)

// DartUpgrader implements Upgrader for Dart/Flutter pub packages.
type DartUpgrader struct{}

func (DartUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeDart(projectDir, pkgName, newVersion)
}

// DartCapDiffer implements CapDiffer for Dart/Flutter pub packages.
type DartCapDiffer struct{}

func (DartCapDiffer) DiffCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}

func analyzeDart(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := dartCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the currently installed project directory.
	oldCaps := dartadapter.Detect(projectDir)

	// New capabilities: use old caps as fallback (no package download available).
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// dartCurrentVersion reads the installed version from pubspec.lock.
func dartCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := dartadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in pubspec.lock", pkgName)
}
