package upgrade

import (
	"fmt"

	javaadapter "github.com/1homsi/gorisk/internal/adapters/java"
	"github.com/1homsi/gorisk/internal/report"
)

// JavaUpgrader implements Upgrader for Java/Maven/Gradle packages.
type JavaUpgrader struct{}

func (JavaUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeJava(projectDir, pkgName, newVersion)
}

// JavaCapDiffer implements CapDiffer for Java packages.
type JavaCapDiffer struct{}

func (JavaCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffJavaCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeJava(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := javaCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Java source.
	oldCaps := javaadapter.Detect(projectDir)

	// New capabilities: without downloading Maven/Gradle artifacts, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// javaCurrentVersion reads the installed version from the Java lockfile.
func javaCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := javaadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Java lockfile", pkgName)
}

func diffJavaCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Java
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
