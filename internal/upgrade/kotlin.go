package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	kotlinadapter "github.com/1homsi/gorisk/internal/adapters/kotlin"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

// KotlinUpgrader implements Upgrader for Kotlin/Gradle packages.
type KotlinUpgrader struct{}

func (KotlinUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeKotlin(projectDir, pkgName, newVersion)
}

// KotlinCapDiffer implements CapDiffer for Kotlin/Gradle packages.
type KotlinCapDiffer struct{}

func (KotlinCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffKotlinCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeKotlin(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := kotlinCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	oldCaps := kotlinProjectCaps(projectDir)
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// kotlinCurrentVersion reads the installed version from the Gradle build files.
func kotlinCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := kotlinadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Gradle build files", pkgName)
}

// kotlinProjectCaps returns capabilities for the Kotlin project directory.
func kotlinProjectCaps(projectDir string) capability.CapabilitySet {
	if _, err := os.Stat(projectDir); err != nil {
		return capability.CapabilitySet{}
	}
	return kotlinadapter.Detect(filepath.Clean(projectDir))
}

func diffKotlinCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}
