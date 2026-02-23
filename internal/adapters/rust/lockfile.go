package rust

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RustPackage represents a Rust dependency extracted from a lockfile.
type RustPackage struct {
	Name         string
	Version      string
	Dir          string
	Dependencies []string
	Direct       bool
}

// Load detects and parses the Rust dependency lockfile in dir.
// Detection order: Cargo.lock → Cargo.toml
func Load(dir string) ([]RustPackage, error) {
	switch {
	case fileExists(filepath.Join(dir, "Cargo.lock")):
		return loadCargoLock(dir)
	case fileExists(filepath.Join(dir, "Cargo.toml")):
		return loadCargoToml(dir)
	}
	return nil, fmt.Errorf("no Rust lockfile found (looked for Cargo.lock, Cargo.toml) in %s", dir)
}

// ---------------------------------------------------------------------------
// Cargo.lock (TOML v3 format)
// ---------------------------------------------------------------------------

// loadCargoLock parses a Cargo.lock file. Each package is introduced by a
// [[package]] header and contains name, version, and optional dependencies.
//
// Example:
//
//	[[package]]
//	name = "serde"
//	version = "1.0.193"
//	source = "registry+https://..."
//	dependencies = [
//	  "serde_derive",
//	]
func loadCargoLock(dir string) ([]RustPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.lock"))
	if err != nil {
		return nil, fmt.Errorf("read Cargo.lock: %w", err)
	}

	rootPkg := readCargoTomlName(dir)
	directDeps := readCargoTomlDeps(dir)

	var packages []RustPackage
	var cur *RustPackage
	inDeps := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// New package section.
		if trimmed == "[[package]]" {
			if cur != nil && cur.Name != "" {
				packages = append(packages, *cur)
			}
			cur = &RustPackage{}
			inDeps = false
			continue
		}

		if cur == nil {
			continue
		}

		// Dependencies array start.
		if strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "[") {
			inDeps = true
			// Handle inline: dependencies = ["foo", "bar"]
			if strings.Contains(trimmed, "]") {
				extractInlineDeps(trimmed, cur)
				inDeps = false
			}
			continue
		}

		// Closing bracket ends the dependencies list.
		if inDeps && trimmed == "]" {
			inDeps = false
			continue
		}

		// Dependency entries inside the array.
		if inDeps && strings.HasPrefix(trimmed, `"`) {
			// "dep-name version" or just "dep-name"
			raw := strings.Trim(trimmed, `",`)
			depName := strings.Fields(raw)[0]
			if depName != "" {
				cur.Dependencies = append(cur.Dependencies, depName)
			}
			continue
		}

		// Key = value pairs at package level.
		if kv, val, ok := parseKV(trimmed); ok {
			switch kv {
			case "name":
				cur.Name = val
				cur.Direct = directDeps[val] && val != rootPkg
			case "version":
				cur.Version = val
			}
		}
	}
	if cur != nil && cur.Name != "" {
		packages = append(packages, *cur)
	}

	// Filter out the root package itself.
	var filtered []RustPackage
	for _, p := range packages {
		if p.Name != rootPkg {
			filtered = append(filtered, p)
		}
	}
	return filtered, nil
}

// extractInlineDeps handles the inline form: dependencies = ["foo", "bar"]
func extractInlineDeps(line string, pkg *RustPackage) {
	start := strings.Index(line, "[")
	end := strings.LastIndex(line, "]")
	if start < 0 || end <= start {
		return
	}
	inner := line[start+1 : end]
	for _, raw := range strings.Split(inner, ",") {
		name := strings.Trim(strings.TrimSpace(raw), `"`)
		name = strings.Fields(name)[0] // strip version suffix if any
		if name != "" {
			pkg.Dependencies = append(pkg.Dependencies, name)
		}
	}
}

// ---------------------------------------------------------------------------
// Cargo.toml (minimal — reads [dependencies] section)
// ---------------------------------------------------------------------------

// loadCargoToml parses the [dependencies] section of a Cargo.toml file.
// It handles both simple and table forms:
//
//	serde = "1.0"
//	serde = { version = "1.0", features = ["derive"] }
func loadCargoToml(dir string) ([]RustPackage, error) {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return nil, fmt.Errorf("read Cargo.toml: %w", err)
	}

	var packages []RustPackage
	inDeps := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section headers.
		if strings.HasPrefix(line, "[") {
			inDeps = line == "[dependencies]" ||
				line == "[dev-dependencies]" ||
				line == "[build-dependencies]"
			continue
		}

		if !inDeps {
			continue
		}

		// Parse: name = "version" or name = { version = "...", ... }
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		val := strings.TrimSpace(parts[1])

		// Extract version from simple or inline table form.
		version := ""
		if strings.HasPrefix(val, `"`) {
			version = strings.Trim(val, `"`)
		} else if strings.Contains(val, "version") {
			// Inline table: { version = "1.0", ... }
			if _, v, ok := parseKV(extractVersionField(val)); ok {
				version = v
			}
		}

		packages = append(packages, RustPackage{
			Name:    name,
			Version: version,
			Direct:  true,
		})
	}
	return packages, nil
}

// extractVersionField extracts "version = \"...\"" from an inline TOML table string.
func extractVersionField(s string) string {
	// Strip surrounding { } if present.
	s = strings.Trim(s, "{ }")
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(field, "version") {
			return field
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readCargoTomlName returns the package name declared in Cargo.toml.
func readCargoTomlName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return ""
	}
	inPkg := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[package]" {
			inPkg = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPkg = false
		}
		if inPkg {
			if k, v, ok := parseKV(line); ok && k == "name" {
				return v
			}
		}
	}
	return ""
}

// readCargoTomlDeps returns the set of direct dependency names from Cargo.toml.
func readCargoTomlDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return nil
	}
	direct := make(map[string]bool)
	inDeps := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDeps = line == "[dependencies]" ||
				line == "[dev-dependencies]" ||
				line == "[build-dependencies]"
			continue
		}
		if inDeps && strings.Contains(line, "=") {
			name := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
			if name != "" {
				direct[name] = true
			}
		}
	}
	return direct
}

// parseKV parses a TOML-style "key = \"value\"" or "key = value" line.
// Returns the key, unquoted value, and true on success.
func parseKV(line string) (string, string, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+1:])
	val = strings.Trim(val, `"`)
	return key, val, true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
