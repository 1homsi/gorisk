package upgrade

import (
	"fmt"

	luaadapter "github.com/1homsi/gorisk/internal/adapters/lua"
	"github.com/1homsi/gorisk/internal/report"
)

// LuaUpgrader implements Upgrader for Lua packages.
type LuaUpgrader struct{}

func (LuaUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeLua(projectDir, pkgName, newVersion)
}

// LuaCapDiffer implements CapDiffer for Lua packages.
type LuaCapDiffer struct{}

func (LuaCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffLuaCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeLua(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := luaCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Lua source.
	oldCaps := luaadapter.Detect(projectDir)

	// New capabilities: without downloading LuaRocks packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// luaCurrentVersion reads the installed version from luarocks.lock.
func luaCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := luaadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Lua dependency file", pkgName)
}

func diffLuaCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Lua
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
