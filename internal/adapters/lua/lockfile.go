// Package lua implements a gorisk analyzer for Lua projects.
// It supports luarocks.lock and *.rockspec files.
package lua

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LuaPackage represents a Lua dependency extracted from a lockfile.
type LuaPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Lua dependency manifest in dir.
// Tries luarocks.lock first, then falls back to *.rockspec.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []LuaPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("lua.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	lockPath := filepath.Join(dir, "luarocks.lock")
	if fileExists(lockPath) {
		return loadLuarocksLock(dir)
	}

	rockspecs, _ := filepath.Glob(filepath.Join(dir, "*.rockspec"))
	if len(rockspecs) > 0 {
		return loadRockspec(rockspecs[0])
	}

	return nil, fmt.Errorf("no Lua lockfile found (looked for luarocks.lock, *.rockspec) in %s", dir)
}

// ---------------------------------------------------------------------------
// luarocks.lock
// ---------------------------------------------------------------------------

// loadLuarocksLock parses a luarocks.lock TOML-ish file.
//
// Format:
//
//	locks_version = "1.0.0"
//
//	[dependencies]
//	  [dependencies.luasocket]
//	  version = "3.1.0-1"
func loadLuarocksLock(dir string) ([]LuaPackage, error) {
	path := filepath.Join(dir, "luarocks.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []LuaPackage
	var curPkg *LuaPackage

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "locks_version") {
			curPkg = nil
			continue
		}

		// Section header: [dependencies.pkgname]
		if strings.HasPrefix(trimmed, "[dependencies.") && strings.HasSuffix(trimmed, "]") {
			// Extract package name from "[dependencies.NAME]".
			inner := trimmed[len("[dependencies."):]
			inner = strings.TrimSuffix(inner, "]")
			name := strings.TrimSpace(inner)
			if name == "" {
				curPkg = nil
				continue
			}
			pkgs = append(pkgs, LuaPackage{
				Name:   name,
				Direct: false,
			})
			curPkg = &pkgs[len(pkgs)-1]
			continue
		}

		// Skip the top-level [dependencies] header.
		if trimmed == "[dependencies]" {
			curPkg = nil
			continue
		}

		// version = "X.Y.Z" field inside a package section.
		if curPkg != nil {
			if versionKey, versionVal, ok := strings.Cut(trimmed, "="); ok {
				if strings.TrimSpace(versionKey) == "version" {
					ver := strings.Trim(strings.TrimSpace(versionVal), `"`)
					curPkg.Version = ver
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

	// Mark direct deps from rockspec.
	rockspecs, _ := filepath.Glob(filepath.Join(dir, "*.rockspec"))
	if len(rockspecs) > 0 {
		direct := readRockspecDirectDeps(rockspecs[0])
		for i := range pkgs {
			if direct[pkgs[i].Name] {
				pkgs[i].Direct = true
			}
		}
	}

	return pkgs, nil
}

// ---------------------------------------------------------------------------
// *.rockspec (fallback)
// ---------------------------------------------------------------------------

// reRockspecDep matches quoted dependency strings inside a dependencies block.
// e.g. "luasocket >= 3.0" or "luasec"
var reRockspecDep = regexp.MustCompile(`["']([^"']+)["']`)

// loadRockspec parses dependencies from a *.rockspec file.
// All packages are Direct=true.
func loadRockspec(path string) ([]LuaPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	names := parseRockspecDeps(data)
	if len(names) == 0 {
		return nil, nil
	}

	pkgs := make([]LuaPackage, 0, len(names))
	for _, name := range names {
		pkgs = append(pkgs, LuaPackage{
			Name:   name,
			Direct: true,
		})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// rockspec helpers
// ---------------------------------------------------------------------------

// readRockspecDirectDeps reads a rockspec file and returns the set of direct
// dependency package names.
func readRockspecDirectDeps(path string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	names := parseRockspecDeps(data)
	direct := make(map[string]bool, len(names))
	for _, n := range names {
		direct[n] = true
	}
	return direct
}

// parseRockspecDeps extracts package names from the dependencies = { ... }
// block in a rockspec file.
func parseRockspecDeps(data []byte) []string {
	content := string(data)

	// Find the dependencies = { ... } block.
	depStart := strings.Index(content, "dependencies")
	if depStart < 0 {
		return nil
	}
	blockStart := strings.Index(content[depStart:], "{")
	if blockStart < 0 {
		return nil
	}
	blockStart += depStart

	blockEnd := strings.Index(content[blockStart:], "}")
	if blockEnd < 0 {
		return nil
	}
	block := content[blockStart : blockStart+blockEnd+1]

	var names []string
	seen := make(map[string]bool)

	for _, m := range reRockspecDep.FindAllStringSubmatch(block, -1) {
		if len(m) < 2 {
			continue
		}
		spec := strings.TrimSpace(m[1])
		// Extract just the package name (before space, >=, >, <, =).
		name, _, _ := strings.Cut(spec, " ")
		name, _, _ = strings.Cut(name, ">")
		name, _, _ = strings.Cut(name, "<")
		name, _, _ = strings.Cut(name, "=")
		name = strings.TrimSpace(name)
		if name == "" || name == "lua" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
