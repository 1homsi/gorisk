// Package cpp implements a gorisk analyzer for C/C++ projects.
// It supports vcpkg.json, conanfile.py, and conanfile.txt.
package cpp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CppPackage represents a C/C++ dependency extracted from a package manifest.
type CppPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the C/C++ dependency manifest in dir.
// Priority: vcpkg.json → conanfile.py → conanfile.txt
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []CppPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("cpp.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "vcpkg.json")):
		return loadVcpkgJSON(dir)
	case fileExists(filepath.Join(dir, "conanfile.py")):
		return loadConanfilePy(dir)
	case fileExists(filepath.Join(dir, "conanfile.txt")):
		return loadConanfileTxt(dir)
	}
	return nil, fmt.Errorf("no C/C++ manifest found (looked for vcpkg.json, conanfile.py, conanfile.txt) in %s", dir)
}

// ---------------------------------------------------------------------------
// vcpkg.json
// ---------------------------------------------------------------------------

// vcpkgManifest mirrors the JSON structure of vcpkg.json.
type vcpkgManifest struct {
	Dependencies []json.RawMessage `json:"dependencies"`
	Overrides    []vcpkgOverride   `json:"overrides"`
}

type vcpkgOverride struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func loadVcpkgJSON(dir string) ([]CppPackage, error) {
	path := filepath.Join(dir, "vcpkg.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var manifest vcpkgManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// Build version override map.
	overrides := make(map[string]string, len(manifest.Overrides))
	for _, o := range manifest.Overrides {
		if o.Name != "" {
			overrides[o.Name] = o.Version
		}
	}

	seen := make(map[string]bool)
	var pkgs []CppPackage

	for _, raw := range manifest.Dependencies {
		// Try string entry first.
		var name string
		if err := json.Unmarshal(raw, &name); err == nil {
			name = strings.TrimSpace(name)
			if name != "" && !seen[name] {
				seen[name] = true
				pkgs = append(pkgs, CppPackage{
					Name:    name,
					Version: overrides[name],
					Direct:  true,
				})
			}
			continue
		}

		// Object entry: {"name": "...", "version>=": "...", "features": [...]}
		var obj struct {
			Name    string `json:"name"`
			Version string `json:"version>="`
		}
		if err := json.Unmarshal(raw, &obj); err == nil && obj.Name != "" {
			obj.Name = strings.TrimSpace(obj.Name)
			if !seen[obj.Name] {
				seen[obj.Name] = true
				ver := obj.Version
				if v, ok := overrides[obj.Name]; ok && v != "" {
					ver = v
				}
				pkgs = append(pkgs, CppPackage{
					Name:    obj.Name,
					Version: ver,
					Direct:  true,
				})
			}
		}
	}

	if len(pkgs) == 0 {
		return nil, nil
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// conanfile.py
// ---------------------------------------------------------------------------

// reConanRequire matches self.requires("name/version") or self.requires("name/version@user/channel").
var reConanRequire = regexp.MustCompile(`self\.requires\s*\(\s*["']([^"'/]+)/([^"'@)]+)`)

// reConanSlash matches a bare "name/version" or "name/version@..." string.
var reConanSlash = regexp.MustCompile(`["']([A-Za-z0-9_\-.]+)/([^"'@\s]+)`)

func loadConanfilePy(dir string) ([]CppPackage, error) {
	path := filepath.Join(dir, "conanfile.py")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var pkgs []CppPackage

	inRequires := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect [requires] section header (sometimes used in .py as comment block).
		if trimmed == "[requires]" {
			inRequires = true
			continue
		}
		// Exit [requires] on next section header.
		if strings.HasPrefix(trimmed, "[") && trimmed != "[requires]" {
			inRequires = false
		}

		// self.requires("name/version") style.
		if m := reConanRequire.FindStringSubmatch(line); m != nil {
			name := strings.TrimSpace(m[1])
			version := strings.TrimSpace(m[2])
			if name != "" && !seen[name] {
				seen[name] = true
				pkgs = append(pkgs, CppPackage{Name: name, Version: version, Direct: true})
			}
			continue
		}

		// [requires] section bare entries.
		if inRequires {
			if m := reConanSlash.FindStringSubmatch(line); m != nil {
				name := strings.TrimSpace(m[1])
				version := strings.TrimSpace(m[2])
				if name != "" && !seen[name] {
					seen[name] = true
					pkgs = append(pkgs, CppPackage{Name: name, Version: version, Direct: true})
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// conanfile.txt
// ---------------------------------------------------------------------------

func loadConanfileTxt(dir string) ([]CppPackage, error) {
	path := filepath.Join(dir, "conanfile.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var pkgs []CppPackage

	inRequires := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Section header.
		if strings.HasPrefix(trimmed, "[") {
			inRequires = trimmed == "[requires]"
			continue
		}

		if !inRequires {
			continue
		}

		// Each non-empty, non-comment line in [requires] is "name/version"
		// or "name/version@user/channel".
		name, rest, ok := strings.Cut(trimmed, "/")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		// Version ends at @ or end of string.
		version, _, _ := strings.Cut(rest, "@")
		version = strings.TrimSpace(version)
		if name == "" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			pkgs = append(pkgs, CppPackage{Name: name, Version: version, Direct: true})
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
