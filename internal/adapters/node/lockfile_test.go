package node

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Malformed / empty input tests — verify no panic and graceful handling
// ---------------------------------------------------------------------------

func TestLoadPackageLockEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error for empty package-lock.json: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty file, got %d", len(pkgs))
	}
}

func TestLoadPackageLockMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for malformed package-lock.json, got nil")
	}
}

func TestLoadPackageLockV3NoDependencies(t *testing.T) {
	// v3 lockfile: has "packages" but no "dependencies" key.
	dir := t.TempDir()
	content := `{
  "name": "myapp",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "myapp",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "debug": "^2.6.9"
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error for v3 lockfile: %v", err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "express" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'express' to be parsed from v3 package-lock.json")
	}
}

func TestLoadYarnLockEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error for empty yarn.lock: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty yarn.lock, got %d", len(pkgs))
	}
}

func TestLoadYarnLockMalformed(t *testing.T) {
	// yarn.lock with no valid package declarations — should return empty, not error.
	dir := t.TempDir()
	content := `# yarn lockfile v1
# just a comment file with no packages
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error for comment-only yarn.lock: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestLoadYarnLockDuplicateEntries(t *testing.T) {
	// yarn.lock can have multiple aliases pointing to the same package.
	// Ensure duplicates are deduplicated.
	dir := t.TempDir()
	content := `# yarn lockfile v1

"debug@^2.0.0", "debug@^2.6.9":
  version "2.6.9"
  resolved "https://registry.yarnpkg.com/debug/-/debug-2.6.9.tgz"
  integrity sha512-xxx

`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	count := 0
	for _, p := range pkgs {
		if p.Name == "debug" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 'debug' entry (deduplication), got %d", count)
	}
}

func TestLoadYarnLockNoQuotedPaths(t *testing.T) {
	// yarn.lock entry without quoted package name.
	dir := t.TempDir()
	content := `# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "express" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'express' to be parsed from unquoted yarn.lock entry")
	}
}

func TestLoadPnpmLockEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error for empty pnpm-lock.yaml: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty pnpm-lock.yaml, got %d", len(pkgs))
	}
}

func TestLoadPnpmLockNoImportersSection(t *testing.T) {
	// pnpm-lock.yaml with no importers: section — should not panic.
	dir := t.TempDir()
	content := `lockfileVersion: '6.0'
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error for pnpm-lock.yaml without importers: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestLoadPnpmLockMalformed(t *testing.T) {
	// Truncated / random bytes — should not panic.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9'\npackages:\n  /badentry"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Should not panic and should return empty or partial result.
	_, _ = Load(dir)
}

func TestLoadNoLockfile(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error when no lockfile is present")
	}
}

// ---------------------------------------------------------------------------
// Basic well-formed tests
// ---------------------------------------------------------------------------

func TestLoadPackageLockV2(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "myapp",
  "lockfileVersion": 2,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {"debug": "^2.6.9"}
    },
    "node_modules/debug": {
      "version": "2.6.9"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	byName := make(map[string]NpmPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if _, ok := byName["express"]; !ok {
		t.Error("expected 'express' in packages")
	}
	if byName["express"].Version != "4.18.2" {
		t.Errorf("express version: got %q, want 4.18.2", byName["express"].Version)
	}
}

func TestLoadYarnLockBasic(t *testing.T) {
	dir := t.TempDir()
	content := `# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  dependencies:
    debug "^2.6.9"

debug@^2.6.9:
  version "2.6.9"
  resolved "https://registry.yarnpkg.com/debug/-/debug-2.6.9.tgz"

`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	byName := make(map[string]NpmPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if _, ok := byName["express"]; !ok {
		t.Error("expected 'express'")
	}
	if byName["express"].Version != "4.18.2" {
		t.Errorf("express version: got %q, want 4.18.2", byName["express"].Version)
	}
	found := false
	for _, dep := range byName["express"].Dependencies {
		if dep == "debug" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'debug' as a dependency of 'express'")
	}
}
