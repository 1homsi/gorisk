package node

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

// NpmPackage represents an npm package extracted from a lockfile.
type NpmPackage struct {
	Name         string
	Version      string
	Dir          string
	Dependencies []string
	Direct       bool
}

// Load detects the lockfile type in dir and parses it.
// It tries package-lock.json, then yarn.lock, then pnpm-lock.yaml.
func Load(dir string) ([]NpmPackage, error) {
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err == nil {
		return loadPackageLock(dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
		return loadYarnLock(dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "pnpm-lock.yaml")); err == nil {
		return loadPnpmLock(dir)
	}
	return nil, fmt.Errorf("no lockfile found (looked for package-lock.json, yarn.lock, pnpm-lock.yaml) in %s", dir)
}

// ---------------------------------------------------------------------------
// package-lock.json (v1, v2, v3)
// ---------------------------------------------------------------------------

type packageLockJSON struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Dependencies    map[string]lockDepV1 `json:"dependencies"`
	Packages        map[string]lockPkgV2 `json:"packages"`
}

type lockDepV1 struct {
	Version      string               `json:"version"`
	Requires     map[string]string    `json:"requires"`
	Dependencies map[string]lockDepV1 `json:"dependencies"`
}

type lockPkgV2 struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	Dev          bool              `json:"dev"`
	Link         bool              `json:"link"`
}

func loadPackageLock(dir string) ([]NpmPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	var lf packageLockJSON
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	directDeps := readDirectDeps(dir)

	if lf.LockfileVersion >= 2 && len(lf.Packages) > 0 {
		return parsePackageLockV2(dir, lf.Packages, directDeps), nil
	}
	return parsePackageLockV1(dir, lf.Dependencies, directDeps), nil
}

func parsePackageLockV2(dir string, packages map[string]lockPkgV2, directDeps map[string]bool) []NpmPackage {
	var result []NpmPackage
	for key, pkg := range packages {
		if key == "" || pkg.Link {
			continue
		}
		// key is like "node_modules/express" or "node_modules/@scope/pkg"
		name := strings.TrimPrefix(key, "node_modules/")
		// Handle nested: node_modules/foo/node_modules/bar → bar
		if idx := strings.LastIndex(name, "node_modules/"); idx >= 0 {
			name = name[idx+len("node_modules/"):]
		}
		var deps []string
		for depName := range pkg.Dependencies {
			deps = append(deps, depName)
		}
		result = append(result, NpmPackage{
			Name:         name,
			Version:      pkg.Version,
			Dir:          filepath.Join(dir, key),
			Dependencies: deps,
			Direct:       directDeps[name],
		})
	}
	return result
}

func parsePackageLockV1(dir string, dependencies map[string]lockDepV1, directDeps map[string]bool) []NpmPackage {
	var result []NpmPackage
	for name, dep := range dependencies {
		var deps []string
		for depName := range dep.Requires {
			deps = append(deps, depName)
		}
		result = append(result, NpmPackage{
			Name:         name,
			Version:      dep.Version,
			Dir:          filepath.Join(dir, "node_modules", name),
			Dependencies: deps,
			Direct:       directDeps[name],
		})
		// Recurse into nested dependencies
		for nestedName, nestedDep := range dep.Dependencies {
			var nestedDeps []string
			for d := range nestedDep.Requires {
				nestedDeps = append(nestedDeps, d)
			}
			result = append(result, NpmPackage{
				Name:         nestedName,
				Version:      nestedDep.Version,
				Dir:          filepath.Join(dir, "node_modules", name, "node_modules", nestedName),
				Dependencies: nestedDeps,
			})
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// yarn.lock (v1 classic)
// ---------------------------------------------------------------------------

func loadYarnLock(dir string) ([]NpmPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "yarn.lock"))
	if err != nil {
		return nil, err
	}
	directDeps := readDirectDeps(dir)
	return parseYarnLock(dir, data, directDeps), nil
}

// rePkgName matches the package name at the start of a yarn.lock declaration:
// "express@^4.x", express@^4.x, "@babel/core@^7.0.0"
var rePkgName = regexp.MustCompile(`^"?(@?[^@"]+)@`)

func parseYarnLock(dir string, data []byte, directDeps map[string]bool) []NpmPackage {
	var result []NpmPackage

	scanner := bufio.NewScanner(bytes.NewReader(data))

	var (
		currentName    string
		currentVersion string
		currentDeps    []string
		inDeps         bool
	)

	flush := func() {
		if currentName == "" {
			return
		}
		result = append(result, NpmPackage{
			Name:         currentName,
			Version:      currentVersion,
			Dir:          filepath.Join(dir, "node_modules", currentName),
			Dependencies: currentDeps,
			Direct:       directDeps[currentName],
		})
		currentName = ""
		currentVersion = ""
		currentDeps = nil
		inDeps = false
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines at the top (# yarn lockfile v1)
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Blank line ends a block
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}

		// Package declaration: starts without leading spaces, not a comment
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
			// Parse the first name from potentially multiple aliases
			// e.g. "express@^4.18.0", "express@^4.x":
			decl := strings.TrimSuffix(strings.TrimSpace(line), ":")
			// Take the first entry
			first := strings.Split(decl, ",")[0]
			first = strings.TrimSpace(first)
			m := rePkgName.FindStringSubmatch(first)
			if m != nil {
				currentName = m[1]
			}
			inDeps = false
			continue
		}

		trimmed := strings.TrimSpace(line)

		if trimmed == "dependencies:" {
			inDeps = true
			continue
		}

		// Stop reading deps if we hit another top-level key in the block
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			inDeps = false
		}

		// Version line: '  version "4.18.2"'
		if strings.HasPrefix(trimmed, "version ") {
			ver := strings.TrimPrefix(trimmed, "version ")
			currentVersion = strings.Trim(ver, `"`)
			continue
		}

		// Dependency line inside dependencies block: '    debug "^2.6.9"'
		if inDeps && strings.HasPrefix(line, "    ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				depName := strings.Trim(parts[0], `"`)
				currentDeps = append(currentDeps, depName)
			}
		}
	}
	flush()

	return result
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (v6, v9 — regex-only, no external YAML dep)
// ---------------------------------------------------------------------------

func loadPnpmLock(dir string) ([]NpmPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
	if err != nil {
		return nil, err
	}
	directDeps := readDirectDeps(dir)
	return parsePnpmLock(dir, data, directDeps), nil
}

// rePnpmPkg matches package entries in pnpm-lock.yaml:
// v6: "  /express@4.18.2:" or "  /@babel/core@7.0.0:"
// v9: "  express@4.18.2:" (no leading slash)
var rePnpmPkg = regexp.MustCompile(`^  /?(@?[^@/\s][^@\s]*)@([^\s:]+):`)

// rePnpmDep matches dependency lines under snapshots/packages: "    debug: 4.3.4"
var rePnpmDep = regexp.MustCompile(`^    ([^:\s]+):\s+(\S+)`)

func parsePnpmLock(dir string, data []byte, directDeps map[string]bool) []NpmPackage {
	seen := make(map[string]bool)
	var result []NpmPackage

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var (
		currentName string
		currentVer  string
		currentDeps []string
		inDepsBlock bool
	)

	flush := func() {
		if currentName == "" {
			return
		}
		key := currentName + "@" + currentVer
		if !seen[key] {
			seen[key] = true
			result = append(result, NpmPackage{
				Name:         currentName,
				Version:      currentVer,
				Dir:          filepath.Join(dir, "node_modules", currentName),
				Dependencies: currentDeps,
				Direct:       directDeps[currentName],
			})
		}
		currentName = ""
		currentVer = ""
		currentDeps = nil
		inDepsBlock = false
	}

	for scanner.Scan() {
		line := scanner.Text()

		if m := rePnpmPkg.FindStringSubmatch(line); m != nil {
			flush()
			currentName = m[1]
			currentVer = m[2]
			inDepsBlock = false
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "dependencies:" {
			inDepsBlock = true
			continue
		}

		// Any line with different indentation resets the deps block
		if len(line) > 0 && !strings.HasPrefix(line, "    ") {
			if !strings.HasPrefix(line, "  ") {
				flush()
			}
			inDepsBlock = false
		}

		if inDepsBlock {
			if m := rePnpmDep.FindStringSubmatch(line); m != nil {
				currentDeps = append(currentDeps, m[1])
			}
		}
	}
	flush()

	return result
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// readDirectDeps reads package.json and returns the set of direct dependency names.
func readDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkgJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkgJSON) != nil {
		return nil
	}
	direct := make(map[string]bool)
	for name := range pkgJSON.Dependencies {
		direct[name] = true
	}
	for name := range pkgJSON.DevDependencies {
		direct[name] = true
	}
	return direct
}
