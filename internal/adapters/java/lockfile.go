package java

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// JavaPackage represents a Java dependency extracted from a lockfile.
type JavaPackage struct {
	Name         string // groupID/artifactID
	GroupID      string
	ArtifactID   string
	Version      string
	Dir          string
	Dependencies []string
	Direct       bool
}

// Load detects and parses the Java dependency lockfile in dir.
// Detection order: pom.xml → build.gradle / gradle.lockfile
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []JavaPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("java.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "pom.xml")):
		return loadPomXML(dir)
	case fileExists(filepath.Join(dir, "gradle.lockfile")):
		return loadGradleLock(dir)
	case fileExists(filepath.Join(dir, "build.gradle")):
		return loadGradleBuild(dir)
	case fileExists(filepath.Join(dir, "build.gradle.kts")):
		return loadGradleBuild(dir)
	}
	return nil, fmt.Errorf("no Java lockfile found (looked for pom.xml, gradle.lockfile, build.gradle) in %s", dir)
}

// ---------------------------------------------------------------------------
// pom.xml (Maven)
// ---------------------------------------------------------------------------

// pomProject mirrors the top-level <project> element in a pom.xml file.
type pomProject struct {
	XMLName      xml.Name        `xml:"project"`
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Version      string          `xml:"version"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
}

// pomDependency mirrors a single <dependency> element.
type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

func loadPomXML(dir string) ([]JavaPackage, error) {
	path := filepath.Join(dir, "pom.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var proj pomProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var packages []JavaPackage
	for _, dep := range proj.Dependencies {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}
		name := dep.GroupID + "/" + dep.ArtifactID
		packages = append(packages, JavaPackage{
			Name:       name,
			GroupID:    dep.GroupID,
			ArtifactID: dep.ArtifactID,
			Version:    dep.Version,
			Direct:     true,
		})
	}
	return packages, nil
}

// ---------------------------------------------------------------------------
// gradle.lockfile
// ---------------------------------------------------------------------------

// gradle.lockfile format: group:artifact:version=config1,config2
// Lines starting with '#' or 'empty=' are skipped.
func loadGradleLock(dir string) ([]JavaPackage, error) {
	path := filepath.Join(dir, "gradle.lockfile")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []JavaPackage
	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		// Strip config suffix: "group:artifact:version=config1,config2" → "group:artifact:version"
		coordPart := strings.SplitN(line, "=", 2)[0]
		parts := strings.Split(coordPart, ":")
		if len(parts) < 3 {
			continue
		}
		groupID := parts[0]
		artifactID := parts[1]
		version := parts[2]
		if groupID == "" || artifactID == "" {
			continue
		}
		name := groupID + "/" + artifactID
		packages = append(packages, JavaPackage{
			Name:       name,
			GroupID:    groupID,
			ArtifactID: artifactID,
			Version:    version,
			Direct:     true,
		})
	}
	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}
	return packages, nil
}

// ---------------------------------------------------------------------------
// build.gradle / build.gradle.kts (regex-based text parse)
// ---------------------------------------------------------------------------

// loadGradleBuild parses a build.gradle or build.gradle.kts for dependency
// declarations of the form:
//
//	implementation 'group:artifact:version'
//	implementation("group:artifact:version")
func loadGradleBuild(dir string) ([]JavaPackage, error) {
	path := filepath.Join(dir, "build.gradle")
	if !fileExists(path) {
		path = filepath.Join(dir, "build.gradle.kts")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []JavaPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// Extract quoted or parenthesised coordinate string.
		coord := extractGradleCoord(line)
		if coord == "" {
			continue
		}
		parts := strings.Split(coord, ":")
		if len(parts) < 2 {
			continue
		}
		groupID := parts[0]
		artifactID := parts[1]
		if groupID == "" || artifactID == "" {
			continue
		}
		version := ""
		if len(parts) >= 3 {
			version = parts[2]
		}
		name := groupID + "/" + artifactID
		if seen[name] {
			continue
		}
		seen[name] = true
		packages = append(packages, JavaPackage{
			Name:       name,
			GroupID:    groupID,
			ArtifactID: artifactID,
			Version:    version,
			Direct:     true,
		})
	}
	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", filepath.Base(path), lineNo, err)
	}
	return packages, nil
}

// extractGradleCoord extracts a "group:artifact:version" coordinate from a
// Gradle dependency declaration line.
func extractGradleCoord(line string) string {
	// Look for single or double quoted strings containing at least one colon.
	for _, quote := range []byte{'"', '\''} {
		q := string(quote)
		start := strings.Index(line, q)
		if start < 0 {
			continue
		}
		rest := line[start+1:]
		end := strings.Index(rest, q)
		if end < 0 {
			continue
		}
		candidate := rest[:end]
		if strings.Contains(candidate, ":") {
			return candidate
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
