package upgrade

import (
	"fmt"

	erlangadapter "github.com/1homsi/gorisk/internal/adapters/erlang"
	"github.com/1homsi/gorisk/internal/report"
)

// ErlangUpgrader implements Upgrader for Erlang packages.
type ErlangUpgrader struct{}

func (ErlangUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeErlang(projectDir, pkgName, newVersion)
}

// ErlangCapDiffer implements CapDiffer for Erlang packages.
type ErlangCapDiffer struct{}

func (ErlangCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffErlangCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeErlang(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := erlangCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for Erlang source.
	oldCaps := erlangadapter.Detect(projectDir)

	// New capabilities: without downloading Hex packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// erlangCurrentVersion reads the installed version from rebar.lock or rebar.config.
func erlangCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := erlangadapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in Erlang dependency file", pkgName)
}

func diffErlangCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary Erlang
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
