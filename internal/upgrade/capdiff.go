package upgrade

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	"github.com/1homsi/gorisk/internal/capability"
)

type CapDiff struct {
	Package   string
	Added     capability.CapabilitySet
	Removed   capability.CapabilitySet
	Escalated bool
}

// CapDiffer compares the capability sets of two versions of a package.
type CapDiffer interface {
	DiffCapabilities(modulePath, oldVersion, newVersion string) ([]CapDiff, error)
}

// GoCapDiffer implements CapDiffer for Go modules.
type GoCapDiffer struct{}

func (GoCapDiffer) DiffCapabilities(modulePath, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffGoCapabilities(modulePath, oldVersion, newVersion)
}

// NodeCapDiffer implements CapDiffer for npm packages.
type NodeCapDiffer struct{}

func (NodeCapDiffer) DiffCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	return diffNodeCapabilities(pkgName, oldVersion, newVersion)
}

func diffGoCapabilities(modulePath, oldVersion, newVersion string) ([]CapDiff, error) {
	oldDir, err := os.MkdirTemp("", "gorisk-old-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(oldDir)

	newDir, err := os.MkdirTemp("", "gorisk-new-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(newDir)

	if err := goScaffoldTempModule(oldDir, modulePath, oldVersion); err != nil {
		return nil, fmt.Errorf("scaffold old: %w", err)
	}
	if err := goScaffoldTempModule(newDir, modulePath, newVersion); err != nil {
		return nil, fmt.Errorf("scaffold new: %w", err)
	}

	oldCaps, err := scanDirCapabilities(oldDir, modulePath)
	if err != nil {
		return nil, fmt.Errorf("scan old: %w", err)
	}
	newCaps, err := scanDirCapabilities(newDir, modulePath)
	if err != nil {
		return nil, fmt.Errorf("scan new: %w", err)
	}

	return buildDiffs(oldCaps, newCaps), nil
}

func scanDirCapabilities(dir, modulePath string) (map[string]capability.CapabilitySet, error) {
	cmd := exec.Command("go", "list", "-json", "-deps", modulePath+"/...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	caps := make(map[string]capability.CapabilitySet)
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p struct {
			ImportPath string   `json:"ImportPath"`
			Dir        string   `json:"Dir"`
			GoFiles    []string `json:"GoFiles"`
			Standard   bool     `json:"Standard"`
			Module     *struct {
				Path string `json:"Path"`
			} `json:"Module"`
		}
		if err := dec.Decode(&p); err != nil {
			continue
		}
		if p.Standard || p.Dir == "" || len(p.GoFiles) == 0 {
			continue
		}
		if p.Module == nil || p.Module.Path != modulePath {
			continue
		}
		cs, err := goadapter.DetectPackage(p.Dir, p.GoFiles)
		if err != nil {
			continue
		}
		caps[p.ImportPath] = cs
	}
	return caps, nil
}

func buildDiffs(oldCaps, newCaps map[string]capability.CapabilitySet) []CapDiff {
	allPkgs := make(map[string]struct{})
	for p := range oldCaps {
		allPkgs[p] = struct{}{}
	}
	for p := range newCaps {
		allPkgs[p] = struct{}{}
	}

	allCaps := []capability.Capability{
		capability.CapFSRead, capability.CapFSWrite, capability.CapNetwork,
		capability.CapExec, capability.CapEnv, capability.CapUnsafe,
		capability.CapCrypto, capability.CapReflect, capability.CapPlugin,
	}

	var diffs []CapDiff
	for pkg := range allPkgs {
		old := oldCaps[pkg]
		nw := newCaps[pkg]

		var added, removed capability.CapabilitySet
		for _, c := range allCaps {
			if nw.Has(c) && !old.Has(c) {
				added.Add(c)
			}
			if old.Has(c) && !nw.Has(c) {
				removed.Add(c)
			}
		}

		if added.IsEmpty() && removed.IsEmpty() {
			continue
		}

		escalated := added.Has(capability.CapExec) ||
			added.Has(capability.CapNetwork) ||
			added.Has(capability.CapUnsafe) ||
			added.Has(capability.CapPlugin)

		diffs = append(diffs, CapDiff{
			Package:   pkg,
			Added:     added,
			Removed:   removed,
			Escalated: escalated,
		})
	}
	return diffs
}

// diffNodeCapabilities compares capability sets of two npm package versions
// by downloading both from the registry and scanning them.
func diffNodeCapabilities(pkgName, oldVersion, newVersion string) ([]CapDiff, error) {
	oldDir, err := nodeadapter.DownloadPackage(pkgName, oldVersion)
	if err != nil {
		return nil, fmt.Errorf("download %s@%s: %w", pkgName, oldVersion, err)
	}
	defer os.RemoveAll(oldDir)

	newDir, err := nodeadapter.DownloadPackage(pkgName, newVersion)
	if err != nil {
		return nil, fmt.Errorf("download %s@%s: %w", pkgName, newVersion, err)
	}
	defer os.RemoveAll(newDir)

	oldCaps := map[string]capability.CapabilitySet{pkgName: nodeadapter.Detect(oldDir)}
	newCaps := map[string]capability.CapabilitySet{pkgName: nodeadapter.Detect(newDir)}

	return buildDiffs(oldCaps, newCaps), nil
}
