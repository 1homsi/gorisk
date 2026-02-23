package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	scalaadapter "github.com/1homsi/gorisk/internal/adapters/scala"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
)

// ScalaUpgrader implements Upgrader for Scala/sbt packages.
type ScalaUpgrader struct{}

func (ScalaUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeScala(projectDir, pkgName, newVersion)
}

// ScalaCapDiffer implements CapDiffer for Scala/sbt packages.
type ScalaCapDiffer struct{}

func (ScalaCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffScalaCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeScala(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := scalaCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	oldCaps := scalaProjectCaps(projectDir)
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// scalaCurrentVersion reads the installed version from build.sbt.
func scalaCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := scalaadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in build.sbt", pkgName)
}

// scalaProjectCaps returns capabilities for the Scala project directory.
func scalaProjectCaps(projectDir string) capability.CapabilitySet {
	if _, err := os.Stat(projectDir); err != nil {
		return capability.CapabilitySet{}
	}
	return scalaadapter.Detect(filepath.Clean(projectDir))
}

func diffScalaCapabilities(_, _, _ string) ([]CapDiff, error) {
	return []CapDiff{}, nil
}
