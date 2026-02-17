package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/tools/go/packages"

	"github.com/1homsi/gorisk/internal/report"
)

func Analyze(projectDir, modulePath, newVersion string) (report.UpgradeReport, error) {
	oldVersion, err := currentVersion(projectDir, modulePath)
	if err != nil {
		return report.UpgradeReport{}, fmt.Errorf("resolve current version: %w", err)
	}

	r := report.UpgradeReport{
		Module: modulePath,
		OldVer: oldVersion,
		NewVer: newVersion,
		Risk:   "LOW",
	}

	oldPkgs, err := loadModulePackages(projectDir, modulePath)
	if err != nil {
		return r, fmt.Errorf("load old packages: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "gorisk-upgrade-*")
	if err != nil {
		return r, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := scaffoldTempModule(tmpDir, modulePath, newVersion); err != nil {
		return r, fmt.Errorf("scaffold temp module: %w", err)
	}

	newPkgs, err := loadModulePackages(tmpDir, modulePath)
	if err != nil {
		return r, fmt.Errorf("load new packages: %w", err)
	}

	oldByPath := make(map[string]*packages.Package)
	for _, p := range oldPkgs {
		oldByPath[p.PkgPath] = p
	}

	for _, newPkg := range newPkgs {
		oldPkg, ok := oldByPath[newPkg.PkgPath]
		if !ok {
			continue
		}
		if newPkg.Types == nil || oldPkg.Types == nil {
			continue
		}
		breaking := diffScopes(oldPkg.Types, newPkg.Types)
		r.Breaking = append(r.Breaking, breaking...)
	}

	oldModPaths := modPaths(oldPkgs)
	newModPaths := modPaths(newPkgs)
	for mp := range newModPaths {
		if mp == modulePath {
			continue
		}
		if _, existed := oldModPaths[mp]; !existed {
			r.NewDeps = append(r.NewDeps, mp)
		}
	}

	switch {
	case len(r.Breaking) > 0:
		r.Risk = "HIGH"
	case len(r.NewDeps) > 0:
		r.Risk = "MEDIUM"
	}

	return r, nil
}

func currentVersion(dir, modulePath string) (string, error) {
	cmd := exec.Command("go", "list", "-m", "-json", modulePath)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	var m struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "", err
	}
	return m.Version, nil
}

func loadModulePackages(dir, modulePath string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Dir:  dir,
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedDeps | packages.NeedModule,
	}
	return packages.Load(cfg, modulePath+"/...")
}

func scaffoldTempModule(dir, modulePath, version string) error {
	gomod := fmt.Sprintf("module gorisk-temp\n\ngo 1.22\n\nrequire %s %s\n", modulePath, version)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		return err
	}
	main := fmt.Sprintf("package main\nimport _ %q\nfunc main() {}\n", modulePath)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0600); err != nil {
		return err
	}
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = dir
	return cmd.Run()
}

func modPaths(pkgs []*packages.Package) map[string]struct{} {
	out := make(map[string]struct{})
	for _, p := range pkgs {
		if p.Module != nil {
			out[p.Module.Path] = struct{}{}
		}
	}
	return out
}
