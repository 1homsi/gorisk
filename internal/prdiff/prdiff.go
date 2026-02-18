package prdiff

import "github.com/1homsi/gorisk/internal/capability"

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

// Differ compares dependency changes between two git refs.
type Differ interface {
	Diff(baseRef, headRef string) (PRDiffReport, error)
}

// GoDiffer implements Differ by parsing go.mod changes.
type GoDiffer struct{}

func (GoDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffGoMod(baseRef, headRef)
}

// NodeDiffer implements Differ by parsing package.json / lockfile changes.
type NodeDiffer struct{}

func (NodeDiffer) Diff(baseRef, headRef string) (PRDiffReport, error) {
	return diffPackageJSON(baseRef, headRef)
}
