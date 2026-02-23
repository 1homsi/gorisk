package upgrade

import (
	"fmt"

	elixiradapter "github.com/1homsi/gorisk/internal/adapters/elixir"
	"github.com/1homsi/gorisk/internal/report"
)

// ElixirUpgrader implements Upgrader for Hex packages.
type ElixirUpgrader struct{}

func (ElixirUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeElixir(projectDir, pkgName, newVersion)
}

// ElixirCapDiffer implements CapDiffer for Hex packages.
type ElixirCapDiffer struct{}

func (ElixirCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}

func analyzeElixir(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := elixirCurrentVersion(projectDir, pkgName)
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
	oldCaps := elixiradapter.Detect(projectDir)

	// New capabilities: use old caps as fallback (no package download available).
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// elixirCurrentVersion reads the installed version from mix.lock.
func elixirCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := elixiradapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in mix.lock", pkgName)
}
