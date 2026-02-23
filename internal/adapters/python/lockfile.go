package python

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

// PythonPackage represents a Python dependency extracted from a lockfile.
type PythonPackage struct {
	Name         string
	Version      string
	Dir          string // path to site-packages/<name>; empty if not installed
	Dependencies []string
	Direct       bool
}

// Load detects and parses the Python dependency lockfile in dir.
// Detection order: pyproject.toml+poetry.lock → Pipfile.lock → requirements.txt
func Load(dir string) ([]PythonPackage, error) {
	// poetry.lock takes priority when both pyproject.toml and poetry.lock exist.
	switch {
	case fileExists(filepath.Join(dir, "poetry.lock")):
		return loadPoetryLock(dir)
	case fileExists(filepath.Join(dir, "Pipfile.lock")):
		return loadPipfileLock(dir)
	case fileExists(filepath.Join(dir, "requirements.txt")):
		return loadRequirementsTxt(dir)
	case fileExists(filepath.Join(dir, "pyproject.toml")):
		return loadPyprojectTOML(dir)
	}
	return nil, fmt.Errorf("no Python lockfile found (looked for poetry.lock, Pipfile.lock, requirements.txt, pyproject.toml) in %s", dir)
}

// ---------------------------------------------------------------------------
// poetry.lock (TOML format)
// ---------------------------------------------------------------------------

var (
	rePoetrySection = regexp.MustCompile(`^\[\[package\]\]`)
	rePoetryKV      = regexp.MustCompile(`^(\w[\w-]*)\s*=\s*(.+)$`)
	rePoetryCat     = regexp.MustCompile(`^\[package\.(dependencies|extras|source)\]`)
)

func loadPoetryLock(dir string) ([]PythonPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "poetry.lock"))
	if err != nil {
		return nil, fmt.Errorf("read poetry.lock: %w", err)
	}

	directDeps := readPoetryDirectDeps(dir)

	var packages []PythonPackage
	var cur *PythonPackage
	inDeps := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		// New package section.
		if rePoetrySection.MatchString(line) {
			if cur != nil {
				packages = append(packages, *cur)
			}
			cur = &PythonPackage{}
			inDeps = false
			continue
		}

		if cur == nil {
			continue
		}

		// Sub-section marker.
		if rePoetryCat.MatchString(line) {
			sub := rePoetryCat.FindStringSubmatch(line)
			inDeps = len(sub) > 1 && sub[1] == "dependencies"
			continue
		}

		// Blank line resets sub-section context.
		if strings.TrimSpace(line) == "" {
			inDeps = false
			continue
		}

		// Dependency entries inside [package.dependencies] take priority.
		if inDeps {
			// dep-name = "^1.0" or dep-name = {version = "^1.0", optional = true}
			if m := rePoetryKV.FindStringSubmatch(line); m != nil {
				depName := strings.TrimSpace(m[1])
				// Skip python version constraints.
				if strings.ToLower(depName) != "python" && depName != "" {
					cur.Dependencies = append(cur.Dependencies, depName)
				}
			}
			continue
		}

		// Key = value pairs at package level (only when not in a sub-section).
		if m := rePoetryKV.FindStringSubmatch(line); m != nil {
			key := strings.ToLower(m[1])
			val := strings.Trim(m[2], `"' `)
			switch key {
			case "name":
				cur.Name = val
				cur.Direct = directDeps[normalizePackageName(val)]
			case "version":
				cur.Version = val
			}
		}
	}
	if cur != nil && cur.Name != "" {
		packages = append(packages, *cur)
	}

	return packages, nil
}

// readPoetryDirectDeps reads pyproject.toml to find direct dependencies.
func readPoetryDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return nil
	}
	direct := make(map[string]bool)
	inDepsSection := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "[tool.poetry.dependencies]", "[project.dependencies]", "[dependencies]":
			inDepsSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDepsSection = false
		}
		if inDepsSection {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				if name != "" && strings.ToLower(name) != "python" {
					direct[normalizePackageName(name)] = true
				}
			}
		}
	}
	return direct
}

// ---------------------------------------------------------------------------
// Pipfile.lock (JSON)
// ---------------------------------------------------------------------------

type pipfileLock struct {
	Default map[string]pipfilePkg `json:"default"`
	Develop map[string]pipfilePkg `json:"develop"`
}

type pipfilePkg struct {
	Version string `json:"version"`
}

func loadPipfileLock(dir string) ([]PythonPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "Pipfile.lock"))
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}

	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	directDeps := readPipfileDirectDeps(dir)

	var packages []PythonPackage
	for name, pkg := range lock.Default {
		ver := strings.TrimPrefix(pkg.Version, "==")
		packages = append(packages, PythonPackage{
			Name:    name,
			Version: ver,
			Direct:  directDeps[normalizePackageName(name)],
		})
	}
	for name, pkg := range lock.Develop {
		ver := strings.TrimPrefix(pkg.Version, "==")
		packages = append(packages, PythonPackage{
			Name:    name,
			Version: ver,
			Direct:  directDeps[normalizePackageName(name)],
		})
	}
	return packages, nil
}

func readPipfileDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "Pipfile"))
	if err != nil {
		return nil
	}
	direct := make(map[string]bool)
	inSection := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[packages]" || line == "[dev-packages]" {
			inSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = false
		}
		if inSection && strings.Contains(line, "=") {
			name := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
			if name != "" {
				direct[normalizePackageName(name)] = true
			}
		}
	}
	return direct
}

// ---------------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------------

var reRequirement = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)`)

func loadRequirementsTxt(dir string) ([]PythonPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		return nil, fmt.Errorf("read requirements.txt: %w", err)
	}

	var packages []PythonPackage
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments, blank lines, and options.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Handle extras: requests[security]==2.28.0 → requests
		line = strings.SplitN(line, "[", 2)[0]

		if m := reRequirement.FindString(line); m != "" {
			// Extract version if present (==, >=, <=, ~=, !=).
			ver := ""
			rest := line[len(m):]
			rest = strings.TrimSpace(rest)
			if v, ok := strings.CutPrefix(rest, "=="); ok {
				ver = strings.Fields(v)[0] // take first token
			}
			packages = append(packages, PythonPackage{
				Name:    m,
				Version: ver,
				Direct:  true, // requirements.txt lists direct deps
			})
		}
	}
	return packages, nil
}

// ---------------------------------------------------------------------------
// pyproject.toml (minimal — no full TOML parser, reads [project] section)
// ---------------------------------------------------------------------------

func loadPyprojectTOML(dir string) ([]PythonPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return nil, fmt.Errorf("read pyproject.toml: %w", err)
	}

	var packages []PythonPackage
	inDeps := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[project]" {
			inDeps = false
			continue
		}
		// [project.dependencies] or dependencies = [...]
		if line == "[project.optional-dependencies]" || line == "[project.dependencies]" {
			inDeps = true
			continue
		}
		if strings.HasPrefix(line, "dependencies") && strings.Contains(line, "=") {
			inDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") && !strings.Contains(line, "dependencies") {
			inDeps = false
		}
		if inDeps {
			// Each dep may be "  \"requests>=2.0\","
			dep := strings.Trim(line, `", []`)
			dep = strings.TrimSpace(dep)
			if dep == "" || strings.HasPrefix(dep, "#") {
				continue
			}
			// Strip version spec.
			if m := reRequirement.FindString(dep); m != "" {
				packages = append(packages, PythonPackage{
					Name:   m,
					Direct: true,
				})
			}
		}
	}
	return packages, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// normalizePackageName lowercases and replaces - and _ with a canonical form
// so "Requests" == "requests" and "my_pkg" == "my-pkg".
func normalizePackageName(name string) string {
	return strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
