package graph

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type listModule struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Dir      string `json:"Dir"`
	Main     bool   `json:"Main"`
	Indirect bool   `json:"Indirect"`
}

type listPackage struct {
	ImportPath string      `json:"ImportPath"`
	Name       string      `json:"Name"`
	Dir        string      `json:"Dir"`
	GoFiles    []string    `json:"GoFiles"`
	Imports    []string    `json:"Imports"`
	Deps       []string    `json:"Deps"`
	Module     *listModule `json:"Module"`
	Standard   bool        `json:"Standard"`
}

func Load(dir string) (*DependencyGraph, error) {
	g := NewDependencyGraph()

	pkgs, err := listPackages(dir)
	if err != nil {
		return nil, fmt.Errorf("go list packages: %w", err)
	}

	for _, lp := range pkgs {
		if lp.Standard {
			continue
		}

		mod := ensureModule(g, lp.Module)

		pkg := &Package{
			ImportPath: lp.ImportPath,
			Name:       lp.Name,
			Module:     mod,
			Dir:        lp.Dir,
			GoFiles:    lp.GoFiles,
			Imports:    lp.Imports,
			Deps:       lp.Deps,
		}

		g.Packages[lp.ImportPath] = pkg
		g.Edges[lp.ImportPath] = lp.Imports

		if mod != nil {
			mod.Packages = append(mod.Packages, pkg)
		}

		if mod != nil && mod.Main {
			g.Main = mod
		}
	}

	if err := loadModGraph(dir, g); err != nil {
		return nil, fmt.Errorf("go mod graph: %w", err)
	}

	return g, nil
}

func ensureModule(g *DependencyGraph, lm *listModule) *Module {
	if lm == nil {
		return nil
	}
	if m, ok := g.Modules[lm.Path]; ok {
		return m
	}
	m := &Module{
		Path:     lm.Path,
		Version:  lm.Version,
		Dir:      lm.Dir,
		Main:     lm.Main,
		Indirect: lm.Indirect,
	}
	g.Modules[lm.Path] = m
	return m
}

func listPackages(dir string) ([]listPackage, error) {
	cmd := exec.Command("go", "list", "-json", "-deps", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var pkgs []listPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p listPackage
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func loadModGraph(dir string, g *DependencyGraph) error {
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		from := modulePathFromModGraph(parts[0])
		to := modulePathFromModGraph(parts[1])

		if _, ok := g.Modules[from]; !ok {
			g.Modules[from] = &Module{Path: from}
		}
		if _, ok := g.Modules[to]; !ok {
			g.Modules[to] = &Module{Path: to}
		}
	}
	return scanner.Err()
}

func modulePathFromModGraph(s string) string {
	at := strings.LastIndex(s, "@")
	if at == -1 {
		return s
	}
	return s[:at]
}
