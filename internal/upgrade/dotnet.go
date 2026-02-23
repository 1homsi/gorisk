package upgrade

import (
	"fmt"

	dotnetadapter "github.com/1homsi/gorisk/internal/adapters/dotnet"
	"github.com/1homsi/gorisk/internal/report"
)

// DotnetUpgrader implements Upgrader for NuGet packages.
type DotnetUpgrader struct{}

func (DotnetUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeDotnet(projectDir, pkgName, newVersion)
}

// DotnetCapDiffer implements CapDiffer for NuGet packages.
type DotnetCapDiffer struct{}

func (DotnetCapDiffer) DiffCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}

func analyzeDotnet(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := dotnetCurrentVersion(projectDir, pkgName)
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
	oldCaps := dotnetadapter.Detect(projectDir)

	// New capabilities: use old caps as fallback (no package download available).
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// dotnetCurrentVersion reads the installed version from packages.lock.json or *.csproj.
func dotnetCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := dotnetadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in packages.lock.json", pkgName)
}
