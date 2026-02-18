package prdiff

import (
	"fmt"

	"github.com/1homsi/gorisk/internal/capability"
)

// ModuleDiff describes a single dependency change in a PR.
type ModuleDiff struct {
	Module       string
	OldVersion   string
	NewVersion   string
	Caps         capability.CapabilitySet
	CapEscalated bool
}

// PRDiffReport summarises all dependency changes introduced by a PR.
type PRDiffReport struct {
	Added   []ModuleDiff
	Removed []string
	Updated []ModuleDiff
}

// Diff returns the dependency changes between baseRef and headRef.
// lang selects the implementation: "go" or "node".
func Diff(baseRef, headRef, lang string) (PRDiffReport, error) {
	switch lang {
	case "go":
		return diffGoMod(baseRef, headRef)
	case "node":
		return diffPackageJSON(baseRef, headRef)
	default:
		return PRDiffReport{}, fmt.Errorf("prdiff: unsupported language %q (supported: go, node)", lang)
	}
}
