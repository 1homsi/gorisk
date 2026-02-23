package upgrade

import (
	"fmt"

	rustadapter "github.com/1homsi/gorisk/internal/adapters/rust"
	"github.com/1homsi/gorisk/internal/report"
)

// RustUpgrader implements Upgrader for Rust crates.
type RustUpgrader struct{}

func (RustUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeRust(projectDir, pkgName, newVersion)
}

// RustCapDiffer implements CapDiffer for Rust crates.
type RustCapDiffer struct{}

func (RustCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffRustCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeRust(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := rustCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Rust source.
	oldCaps := rustadapter.Detect(projectDir)

	// New capabilities: without downloading crates.io packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// rustCurrentVersion reads the installed version from Cargo.lock.
func rustCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := rustadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Cargo.lock", pkgName)
}

func diffRustCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Rust
	// crate versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
