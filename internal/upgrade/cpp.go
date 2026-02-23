package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	cppadapter "github.com/1homsi/gorisk/internal/adapters/cpp"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

// CppUpgrader implements Upgrader for C/C++ packages.
type CppUpgrader struct{}

func (CppUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeCpp(projectDir, pkgName, newVersion)
}

// CppCapDiffer implements CapDiffer for C/C++ packages.
type CppCapDiffer struct{}

func (CppCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffCppCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeCpp(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := cppCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	oldCaps := cppProjectCaps(projectDir)
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// cppCurrentVersion reads the installed version from vcpkg.json or conanfile.txt.
func cppCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := cppadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in C/C++ manifest", pkgName)
}

// cppProjectCaps returns capabilities for the C/C++ project directory.
func cppProjectCaps(projectDir string) capability.CapabilitySet {
	if _, err := os.Stat(projectDir); err != nil {
		return capability.CapabilitySet{}
	}
	return cppadapter.Detect(filepath.Clean(projectDir))
}

func diffCppCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}
