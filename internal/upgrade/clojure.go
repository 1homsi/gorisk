package upgrade

import (
	"fmt"

	clojureadapter "github.com/1homsi/gorisk/internal/adapters/clojure"
	"github.com/1homsi/gorisk/internal/report"
)

// ClojureUpgrader implements Upgrader for Clojure packages.
type ClojureUpgrader struct{}

func (ClojureUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeClojure(projectDir, pkgName, newVersion)
}

// ClojureCapDiffer implements CapDiffer for Clojure packages.
type ClojureCapDiffer struct{}

func (ClojureCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffClojureCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeClojure(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := clojureCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Clojure source.
	oldCaps := clojureadapter.Detect(projectDir)

	// New capabilities: without downloading Maven packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// clojureCurrentVersion reads the installed version from deps.edn or project.clj.
func clojureCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := clojureadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Clojure dependency file", pkgName)
}

func diffClojureCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Clojure
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
