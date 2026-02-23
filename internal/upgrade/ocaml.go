package upgrade

import (
	"fmt"

	ocamladapter "github.com/1homsi/gorisk/internal/adapters/ocaml"
	"github.com/1homsi/gorisk/internal/report"
)

// OCamlUpgrader implements Upgrader for OCaml packages.
type OCamlUpgrader struct{}

func (OCamlUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeOCaml(projectDir, pkgName, newVersion)
}

// OCamlCapDiffer implements CapDiffer for OCaml packages.
type OCamlCapDiffer struct{}

func (OCamlCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffOCamlCapabilities(pkgName, oldVersion, newVersion)
}

func analyzeOCaml(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := ocamlCurrentVersion(projectDir, pkgName)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: pkgName,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	// Old capabilities: scan the project directory for OCaml source.
	oldCaps := ocamladapter.Detect(projectDir)

	// New capabilities: without downloading opam packages, use the same scan.
	newCaps := oldCaps

	if capEscalated(oldCaps, newCaps) {
		r.Risk = "HIGH"
	}

	return r, nil
}

// ocamlCurrentVersion reads the installed version from the opam lockfile.
func ocamlCurrentVersion(projectDir, pkgName string) (string, error) {
	pkgs, err := ocamladapter.Load(projectDir)
	if err != nil {
		return "", err
	}
	for _, p := range pkgs {
		if p.Name == pkgName {
			return p.Version, nil
		}
	}
	return "", fmt.Errorf("package %q not found in OCaml dependency file", pkgName)
}

func diffOCamlCapabilities(_, _, _ string) ([]CapDiff, error) {
	// Stub: without a package registry API, we cannot download arbitrary OCaml
	// package versions. Return an empty diff to indicate no known escalation.
	return []CapDiff{}, nil
}
