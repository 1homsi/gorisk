// Package r implements a gorisk analyzer for R projects.
// It supports renv.lock and DESCRIPTION files.
package r

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RPackage represents an R dependency extracted from a lockfile or DESCRIPTION.
type RPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the R dependency manifest in dir.
// Tries renv.lock first, then falls back to DESCRIPTION.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []RPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("r.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "renv.lock")):
		return loadRenvLock(dir)
	case fileExists(filepath.Join(dir, "DESCRIPTION")):
		return loadDescription(dir)
	}
	return nil, fmt.Errorf("no R lockfile found (looked for renv.lock, DESCRIPTION) in %s", dir)
}

// ---------------------------------------------------------------------------
// renv.lock
// ---------------------------------------------------------------------------

// renvLockFile is the top-level structure of an renv.lock JSON file.
type renvLockFile struct {
	R struct {
		Version string `json:"Version"`
	} `json:"R"`
	Packages map[string]renvPackageEntry `json:"Packages"`
}

type renvPackageEntry struct {
	Package      string   `json:"Package"`
	Version      string   `json:"Version"`
	Requirements []string `json:"Requirements"`
}

// loadRenvLock parses an renv.lock file and optionally reads DESCRIPTION for
// direct dependency information.
func loadRenvLock(dir string) ([]RPackage, error) {
	path := filepath.Join(dir, "renv.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var lock renvLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(lock.Packages) == 0 {
		return nil, nil
	}

	// Collect all packages from the lock. Direct=false by default.
	var pkgs []RPackage
	for _, entry := range lock.Packages {
		name := entry.Package
		if name == "" {
			continue
		}
		pkgs = append(pkgs, RPackage{
			Name:         name,
			Version:      entry.Version,
			Direct:       false,
			Dependencies: entry.Requirements,
		})
	}

	// Mark direct deps from DESCRIPTION (if it exists).
	direct := readDescriptionDirectDeps(dir)
	if len(direct) > 0 {
		for i := range pkgs {
			if direct[pkgs[i].Name] {
				pkgs[i].Direct = true
			}
		}
	}

	return pkgs, nil
}

// ---------------------------------------------------------------------------
// DESCRIPTION (fallback)
// ---------------------------------------------------------------------------

// loadDescription parses a DESCRIPTION file for Imports/Depends declarations.
// All packages are Direct=true and Version is empty.
func loadDescription(dir string) ([]RPackage, error) {
	path := filepath.Join(dir, "DESCRIPTION")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	names := parseDescriptionDeps(data, []string{"Imports", "Depends", "LinkingTo"})
	if len(names) == 0 {
		return nil, nil
	}

	pkgs := make([]RPackage, 0, len(names))
	for _, name := range names {
		pkgs = append(pkgs, RPackage{
			Name:   name,
			Direct: true,
		})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// DESCRIPTION helpers
// ---------------------------------------------------------------------------

// readDescriptionDirectDeps returns the set of package names listed under
// Imports:, Depends:, and LinkingTo: in a DESCRIPTION file.
func readDescriptionDirectDeps(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "DESCRIPTION"))
	if err != nil {
		return nil
	}
	names := parseDescriptionDeps(data, []string{"Imports", "Depends", "LinkingTo"})
	if len(names) == 0 {
		return nil
	}
	direct := make(map[string]bool, len(names))
	for _, n := range names {
		direct[n] = true
	}
	return direct
}

// parseDescriptionDeps extracts package names from the given field names in a
// DESCRIPTION file. Continuation lines start with whitespace. Package names
// are terminated by '(' (version constraint) or comma/newline.
func parseDescriptionDeps(data []byte, fields []string) []string {
	fieldSet := make(map[string]bool, len(fields))
	for _, f := range fields {
		fieldSet[f] = true
	}

	var names []string
	seen := make(map[string]bool)

	inField := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			inField = false
			continue
		}

		// Check if this is a new field header.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inField = false
			fieldName, rest, _ := strings.Cut(line, ":")
			fieldName = strings.TrimSpace(fieldName)
			if fieldSet[fieldName] {
				inField = true
				// The rest of the header line may contain dep names.
				extractDepNames(rest, seen, &names)
			}
			continue
		}

		// Continuation line inside a known field.
		if inField {
			extractDepNames(line, seen, &names)
		}
	}
	return names
}

// extractDepNames splits a comma-separated list of dep specs and appends
// package names (excluding the "R" base runtime) to names.
func extractDepNames(s string, seen map[string]bool, names *[]string) {
	for _, token := range strings.Split(s, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		// Strip version constraint like "(>= 1.4.0)".
		name, _, _ := strings.Cut(token, "(")
		name = strings.TrimSpace(name)
		if name == "" || name == "R" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			*names = append(*names, name)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
