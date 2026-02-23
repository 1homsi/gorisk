package upgrade

import (
	"fmt"

	swiftadapter "github.com/1homsi/gorisk/internal/adapters/swift"
	"github.com/1homsi/gorisk/internal/report"
)

// SwiftUpgrader implements Upgrader for Swift Package Manager packages.
type SwiftUpgrader struct{}

func (SwiftUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeSwift(projectDir, pkgName, newVersion)
}

// SwiftCapDiffer implements CapDiffer for Swift Package Manager packages.
type SwiftCapDiffer struct{}

func (SwiftCapDiffer) DiffCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}

func analyzeSwift(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := swiftCurrentVersion(projectDir, pkgName)
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
	oldCaps := swiftadapter.Detect(projectDir)

	// New capabilities: use old caps as fallback (no package download available).
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// swiftCurrentVersion reads the installed version from Package.resolved.
func swiftCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := swiftadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Package.resolved", pkgName)
}
