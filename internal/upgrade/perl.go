package upgrade

import (
	"fmt"

	perladapter "github.com/1homsi/gorisk/internal/adapters/perl"
	"github.com/1homsi/gorisk/internal/report"
)

// PerlUpgrader implements Upgrader for Perl packages.
type PerlUpgrader struct{}

func (PerlUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzePerl(projectDir, pkgName, newVersion)
}

// PerlCapDiffer implements CapDiffer for Perl packages.
type PerlCapDiffer struct{}

func (PerlCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffPerlCapabilities(pkgName, oldVersion, newVersion)
}

func analyzePerl(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := perlCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Perl source.
	oldCaps := perladapter.Detect(projectDir)

	// New capabilities: without downloading CPAN packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// perlCurrentVersion reads the installed version from cpanfile.snapshot.
func perlCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := perladapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Perl dependency file", pkgName)
}

func diffPerlCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Perl
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
