// Package kotlin implements a gorisk analyzer for Kotlin/Gradle projects.
package kotlin

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// KotlinPackage represents a Kotlin/Gradle dependency.
type KotlinPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// gradleDepConfigs are the Gradle configuration keywords that declare
// direct dependencies in build scripts.
var gradleDepConfigs = []string{
	"implementation",
	"api",
	"testImplementation",
	"testApi",
	"compileOnly",
	"runtimeOnly",
	"testCompileOnly",
	"testRuntimeOnly",
	"annotationProcessor",
	"kapt",
	"ksp",
}

// reKtsQuoted matches: implementation("group:artifact:version") or without version
// Captures group:artifact and optional :version.
var reKtsQuoted = regexp.MustCompile(`"([A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+)(?::([^"]*))?"`)

// reGroovyQuoted matches single or double quoted dep in Groovy build.gradle.
var reGroovyQuoted = regexp.MustCompile(`['"]([A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+)(?::([^'"]*))['"]`)

// Load detects and parses Gradle dependency files in dir.
// Priority: libs.versions.toml → build.gradle.kts → build.gradle
// Load never panics; structured errors are returned on failure.
func Load(dir string) (pkgs []KotlinPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("kotlin.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "gradle", "libs.versions.toml")):
		return loadLibsVersionsToml(filepath.Join(dir, "gradle", "libs.versions.toml"))
	case fileExists(filepath.Join(dir, "libs.versions.toml")):
		return loadLibsVersionsToml(filepath.Join(dir, "libs.versions.toml"))
	case fileExists(filepath.Join(dir, "build.gradle.kts")):
		return loadBuildGradleKts(filepath.Join(dir, "build.gradle.kts"))
	case fileExists(filepath.Join(dir, "build.gradle")):
		return loadBuildGradle(filepath.Join(dir, "build.gradle"))
	}
	return nil, fmt.Errorf("no Kotlin/Gradle build file found (looked for libs.versions.toml, build.gradle.kts, build.gradle) in %s", dir)
}

// ---------------------------------------------------------------------------
// libs.versions.toml (Gradle Version Catalog)
// ---------------------------------------------------------------------------

func loadLibsVersionsToml(path string) ([]KotlinPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	const (
		secNone      = ""
		secVersions  = "versions"
		secLibraries = "libraries"
	)

	versions := make(map[string]string)
	var pkgs []KotlinPackage
	seen := make(map[string]bool)

	section := secNone
	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Section headers: [versions], [libraries], [bundles], [plugins]
		if strings.HasPrefix(trimmed, "[") {
			name := strings.Trim(trimmed, "[]")
			name = strings.TrimSpace(name)
			switch name {
			case "versions":
				section = secVersions
			case "libraries":
				section = secLibraries
			default:
				section = secNone
			}
			continue
		}

		switch section {
		case secVersions:
			// key = "value"  or  key = { ... }  — we only care about simple string values.
			k, v, ok := strings.Cut(trimmed, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"`)
			versions[k] = v

		case secLibraries:
			// alias = { module = "group:artifact", version.ref = "X" }
			// alias = { module = "group:artifact", version = "X" }
			_, rest, ok := strings.Cut(trimmed, "=")
			if !ok {
				continue
			}
			rest = strings.TrimSpace(rest)

			module := extractTomlField(rest, "module")
			if module == "" {
				continue
			}
			module = strings.Trim(module, `"`)

			var version string
			if vref := extractTomlField(rest, "version.ref"); vref != "" {
				vref = strings.Trim(vref, `"`)
				version = versions[vref]
			} else if v := extractTomlField(rest, "version"); v != "" {
				version = strings.Trim(v, `"`)
			}

			key := module
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, KotlinPackage{
				Name:    module,
				Version: version,
				Direct:  true,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// extractTomlField extracts a field value from an inline TOML table string
// such as `{ module = "group:artifact", version.ref = "ktor" }`.
func extractTomlField(s, field string) string {
	needle := field + " ="
	idx := strings.Index(s, needle)
	if idx < 0 {
		// Try without space before =
		needle = field + "="
		idx = strings.Index(s, needle)
		if idx < 0 {
			return ""
		}
	}
	rest := strings.TrimSpace(s[idx+len(needle):])
	// Value ends at comma or closing brace.
	end := strings.IndexAny(rest, ",}")
	if end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

// ---------------------------------------------------------------------------
// build.gradle.kts (Kotlin DSL)
// ---------------------------------------------------------------------------

func loadBuildGradleKts(path string) ([]KotlinPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []KotlinPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !isDepLine(trimmed) {
			continue
		}

		m := reKtsQuoted.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name := m[1]
		version := ""
		if len(m) > 2 {
			version = m[2]
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, KotlinPackage{
			Name:    name,
			Version: version,
			Direct:  true,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// build.gradle (Groovy DSL)
// ---------------------------------------------------------------------------

func loadBuildGradle(path string) ([]KotlinPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []KotlinPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !isDepLine(trimmed) {
			continue
		}

		m := reGroovyQuoted.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name := m[1]
		version := ""
		if len(m) > 2 {
			version = m[2]
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, KotlinPackage{
			Name:    name,
			Version: version,
			Direct:  true,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// isDepLine reports whether a trimmed Gradle line starts with a known
// dependency configuration keyword.
func isDepLine(trimmed string) bool {
	for _, cfg := range gradleDepConfigs {
		if strings.HasPrefix(trimmed, cfg+"(") || strings.HasPrefix(trimmed, cfg+" ") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
