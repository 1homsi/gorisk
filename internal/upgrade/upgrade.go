package upgrade

import "github.com/1homsi/gorisk/internal/report"

// Upgrader compares the current installed version of a package against a
// candidate version and returns an upgrade risk report.
type Upgrader interface {
	Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error)
}

// GoUpgrader implements Upgrader for Go modules.
type GoUpgrader struct{}

func (GoUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeGo(projectDir, pkgName, newVersion)
}

// NodeUpgrader implements Upgrader for npm packages.
type NodeUpgrader struct{}

func (NodeUpgrader) Analyze(projectDir, pkgName, newVersion string) (report.UpgradeReport, error) {
	return analyzeNode(projectDir, pkgName, newVersion)
}
