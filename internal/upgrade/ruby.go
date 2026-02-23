package upgrade

import (
	"fmt"

	rubyadapter "github.com/1homsi/gorisk/internal/adapters/ruby"
	"github.com/1homsi/gorisk/internal/report"
)

// RubyUpgrader implements Upgrader for Ruby gems.
type RubyUpgrader struct{}

func (RubyUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeRuby(projectDir, pkgName, newVersion)
}

// RubyCapDiffer implements CapDiffer for Ruby gems.
type RubyCapDiffer struct{}

func (RubyCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffRubyCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeRuby(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := rubyCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Ruby source.
	oldCaps := rubyadapter.Detect(projectDir)

	// New capabilities: without downloading RubyGems packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// rubyCurrentVersion reads the installed version from Gemfile.lock.
func rubyCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := rubyadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Gemfile.lock", pkgName)
}

func diffRubyCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Ruby
	// gem versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
