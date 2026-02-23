package upgrade

import (
	"fmt"

	juliaadapter "github.com/1homsi/gorisk/internal/adapters/julia"
	"github.com/1homsi/gorisk/internal/report"
)

// JuliaUpgrader implements Upgrader for Julia packages.
type JuliaUpgrader struct{}

func (JuliaUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeJulia(projectDir, pkgName, newVersion)
}

// JuliaCapDiffer implements CapDiffer for Julia packages.
type JuliaCapDiffer struct{}

func (JuliaCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffJuliaCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeJulia(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := juliaCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Julia source.
	oldCaps := juliaadapter.Detect(projectDir)

	// New capabilities: without downloading Julia packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// juliaCurrentVersion reads the installed version from Manifest.toml.
func juliaCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := juliaadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Julia dependency file", pkgName)
}

func diffJuliaCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Julia
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
