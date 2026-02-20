package php

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ComposerPackage represents a PHP package extracted from composer.lock.
type ComposerPackage struct {
	Name         string
	Version      string
	Dir          string // path to vendor/<vendor>/<package>
	Dependencies []string
	Direct       bool
}

// composerLock mirrors the composer.lock JSON structure.
type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

// Load parses composer.lock in dir and returns the resolved packages.
// Packages are looked up in vendor/ for source scanning.
func Load(dir string) ([]ComposerPackage, error) {
	lockPath := filepath.Join(dir, "composer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("no composer.lock found in %s", dir)
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	directDeps := readDirectDeps(dir)

	var result []ComposerPackage
	for _, pkg := range append(lock.Packages, lock.PackagesDev...) {
		var deps []string
		for depName := range pkg.Require {
			// Skip PHP version constraints and extensions (e.g. "php", "ext-json")
			if depName == "php" || len(depName) > 4 && depName[:4] == "ext-" {
				continue
			}
			deps = append(deps, depName)
		}
		result = append(result, ComposerPackage{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Dir:          filepath.Join(dir, "vendor", pkg.Name),
			Dependencies: deps,
			Direct:       directDeps[pkg.Name],
		})
	}

	return result, nil
}

// readDirectDeps reads composer.json and returns the set of direct dependency names.
func readDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		return nil
	}
	var composerJSON struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &composerJSON) != nil {
		return nil
	}
	direct := make(map[string]bool)
	for name := range composerJSON.Require {
		direct[name] = true
	}
	for name := range composerJSON.RequireDev {
		direct[name] = true
	}
	return direct
}
