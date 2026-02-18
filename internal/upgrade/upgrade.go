package upgrade

import (
	"fmt"

	"github.com/1homsi/gorisk/internal/report"
)

// Analyze compares the current installed version of a package against
// newVersion and returns an upgrade risk report.
// lang selects the implementation: "go" or "node".
func Analyze(projectDir, pkgName, newVersion, lang string) (report.UpgradeReport, error) {
	switch lang {
	case "go":
		return analyzeGo(projectDir, pkgName, newVersion)
	case "node":
		return analyzeNode(projectDir, pkgName, newVersion)
	default:
		return report.UpgradeReport{}, fmt.Errorf("upgrade: unsupported language %q (supported: go, node)", lang)
	}
}
