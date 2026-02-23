// Package julia implements a gorisk analyzer for Julia projects.
// It supports Manifest.toml and Project.toml.
package julia

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// JuliaPackage represents a Julia dependency extracted from a lockfile.
type JuliaPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
	UUID         string
}

// Load detects and parses the Julia dependency lockfile in dir.
// Priority: Manifest.toml → Project.toml.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []JuliaPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("julia.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	manifestPath := filepath.Join(dir, "Manifest.toml")
	projectPath := filepath.Join(dir, "Project.toml")

	switch {
	case fileExists(manifestPath):
		return loadManifest(manifestPath, projectPath)
	case fileExists(projectPath):
		return loadProject(projectPath)
	}

	return nil, fmt.Errorf("no Julia lockfile found (looked for Manifest.toml, Project.toml) in %s", dir)
}

// ---------------------------------------------------------------------------
// Manifest.toml
// ---------------------------------------------------------------------------

// loadManifest parses Manifest.toml for the full dependency closure, then
// marks direct deps by reading Project.toml.
func loadManifest(manifestPath, projectPath string) ([]JuliaPackage, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifestPath, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []JuliaPackage
	byName := make(map[string]*JuliaPackage)

	var cur *JuliaPackage

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Section header: [[deps.NAME]]
		if strings.HasPrefix(trimmed, "[[deps.") && strings.HasSuffix(trimmed, "]]") {
			name := trimmed[len("[[deps."):]
			name = strings.TrimSuffix(name, "]]")
			name = strings.TrimSpace(name)
			if name == "" {
				cur = nil
				continue
			}
			pkgs = append(pkgs, JuliaPackage{Name: name})
			byName[name] = &pkgs[len(pkgs)-1]
			cur = byName[name]
			continue
		}

		if cur == nil {
			continue
		}

		// version = "X.Y.Z"
		if key, val, ok := parseTomlKV(trimmed); ok {
			switch key {
			case "version":
				cur.Version = val
			case "uuid":
				cur.UUID = val
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", manifestPath, lineNo, err)
	}

	// Mark direct deps from Project.toml.
	if fileExists(projectPath) {
		directDeps := readProjectDirectDeps(projectPath)
		for i := range pkgs {
			if directDeps[pkgs[i].Name] {
				pkgs[i].Direct = true
			}
		}
	}

	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Project.toml
// ---------------------------------------------------------------------------

// loadProject parses Project.toml [deps] section as a fallback when no
// Manifest.toml is present. All packages are marked Direct=true.
func loadProject(projectPath string) ([]JuliaPackage, error) {
	data, err := os.ReadFile(projectPath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", projectPath, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []JuliaPackage
	seen := make(map[string]bool)
	inDeps := false

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Section header.
		if strings.HasPrefix(trimmed, "[") {
			inDeps = trimmed == "[deps]"
			continue
		}
		if !inDeps {
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// NAME = "uuid"
		name, uuid, ok := parseTomlKV(trimmed)
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, JuliaPackage{
			Name:   name,
			UUID:   uuid,
			Direct: true,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", projectPath, lineNo, err)
	}

	return pkgs, nil
}

// readProjectDirectDeps returns the set of package names listed in the [deps]
// section of Project.toml.
func readProjectDirectDeps(projectPath string) map[string]bool {
	data, err := os.ReadFile(projectPath)
	if err != nil {
		return nil
	}

	direct := make(map[string]bool)
	inDeps := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") {
			inDeps = trimmed == "[deps]"
			continue
		}
		if !inDeps || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		name, _, ok := parseTomlKV(trimmed)
		if ok && name != "" {
			direct[name] = true
		}
	}
	return direct
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseTomlKV parses a line of the form `key = "value"` or `key = value`.
// Returns (key, value, true) on success.
func parseTomlKV(line string) (key, value string, ok bool) {
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	key = strings.TrimSpace(k)
	value = strings.TrimSpace(v)
	// Strip surrounding quotes if present.
	value = strings.Trim(value, `"`)
	return key, value, key != ""
}

// fileExists reports whether path exists on disk.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
