// Package scala implements a gorisk analyzer for Scala/sbt projects.
package scala

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ScalaPackage represents a Scala/sbt dependency.
type ScalaPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// reSbtDep matches sbt dependency declarations of the form:
//
//	"org" %% "name" % "version"
//	"org" % "name" % "version"
//	"org" %% "name" %% "version"
//
// Captures: [1]=org, [2]=name, [3]=version
var reSbtDep = regexp.MustCompile(
	`"([^"]+)"\s*%%?\s*"([^"]+)"\s*%%?\s*"([^"]+)"`,
)

// reSbtDepNoVersion matches deps without explicit version string (2-part only).
var reSbtDepNoVersion = regexp.MustCompile(
	`"([^"]+)"\s*%%?\s*"([^"]+)"`,
)

// Load detects and parses Scala/sbt build files in dir.
// Primary: build.sbt. Supplementary: project/build.properties.
// Load never panics; structured errors are returned on failure.
func Load(dir string) (pkgs []ScalaPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("scala.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	sbtPath := filepath.Join(dir, "build.sbt")
	if !fileExists(sbtPath) {
		return nil, fmt.Errorf("no Scala build file found (looked for build.sbt) in %s", dir)
	}

	pkgs, err := loadBuildSbt(sbtPath)
	if err != nil {
		return nil, err
	}

	// Optionally add sbt version from project/build.properties.
	sbtVersion := readSbtVersion(filepath.Join(dir, "project", "build.properties"))
	if sbtVersion != "" {
		pkgs = append(pkgs, ScalaPackage{
			Name:    "sbt:sbt",
			Version: sbtVersion,
			Direct:  true,
		})
	}

	return pkgs, nil
}

// loadBuildSbt parses a build.sbt file and returns all dependency declarations.
func loadBuildSbt(path string) ([]ScalaPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []ScalaPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		// Skip blank lines and comments.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Try 3-part match (with version) first.
		m := reSbtDep.FindStringSubmatch(line)
		if m != nil {
			org := m[1]
			name := m[2]
			version := m[3]
			key := org + ":" + name
			if !seen[key] {
				seen[key] = true
				pkgs = append(pkgs, ScalaPackage{
					Name:    key,
					Version: version,
					Direct:  true,
				})
			}
			continue
		}

		// Try 2-part match (no version — e.g. in libraryDependencies variable builds).
		m2 := reSbtDepNoVersion.FindStringSubmatch(line)
		if m2 != nil {
			org := m2[1]
			name := m2[2]
			key := org + ":" + name
			if !seen[key] {
				seen[key] = true
				pkgs = append(pkgs, ScalaPackage{
					Name:   key,
					Direct: true,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return pkgs, nil
}

// readSbtVersion reads the sbt.version property from project/build.properties.
func readSbtVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "sbt.version") {
			_, v, ok := strings.Cut(line, "=")
			if ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
