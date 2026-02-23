package r

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadRenvLock(t *testing.T) {
	dir := t.TempDir()

	lockContent := `{
  "R": { "Version": "4.3.2" },
  "Packages": {
    "httr": {
      "Package": "httr",
      "Version": "1.4.7",
      "Source": "Repository",
      "Repository": "CRAN",
      "Requirements": ["curl", "jsonlite", "openssl"]
    },
    "curl": {
      "Package": "curl",
      "Version": "5.2.0",
      "Source": "Repository",
      "Requirements": []
    },
    "jsonlite": {
      "Package": "jsonlite",
      "Version": "1.8.8",
      "Source": "Repository",
      "Requirements": []
    },
    "openssl": {
      "Package": "openssl",
      "Version": "2.1.1",
      "Source": "Repository",
      "Requirements": []
    }
  }
}`
	descContent := `Package: myproject
Title: My R Project
Imports:
    httr (>= 1.4.0),
    jsonlite
Suggests:
    testthat
`
	if err := os.WriteFile(filepath.Join(dir, "renv.lock"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "DESCRIPTION"), []byte(descContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]RPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["httr"]; !ok {
		t.Error("expected 'httr' in packages")
	}
	if byName["httr"].Version != "1.4.7" {
		t.Errorf("httr version: got %q, want %q", byName["httr"].Version, "1.4.7")
	}
	if !byName["httr"].Direct {
		t.Error("httr should be a direct dep (listed in DESCRIPTION Imports)")
	}
	if !byName["jsonlite"].Direct {
		t.Error("jsonlite should be a direct dep (listed in DESCRIPTION Imports)")
	}
	// curl is not in DESCRIPTION, so it should be indirect.
	if byName["curl"].Direct {
		t.Error("curl should be an indirect dep")
	}
	// httr should list its requirements.
	found := false
	for _, dep := range byName["httr"].Dependencies {
		if dep == "curl" {
			found = true
		}
	}
	if !found {
		t.Error("httr should depend on curl")
	}
}

func TestLoadDescription(t *testing.T) {
	dir := t.TempDir()
	descContent := `Package: myproject
Title: My R Project
Version: 0.1.0
Imports:
    httr (>= 1.4.0),
    dplyr,
    ggplot2
Depends:
    R (>= 4.0.0)
Suggests:
    testthat
`
	if err := os.WriteFile(filepath.Join(dir, "DESCRIPTION"), []byte(descContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]RPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["httr"]; !ok {
		t.Error("expected 'httr' in packages")
	}
	if _, ok := byName["dplyr"]; !ok {
		t.Error("expected 'dplyr' in packages")
	}
	if _, ok := byName["ggplot2"]; !ok {
		t.Error("expected 'ggplot2' in packages")
	}
	// "R" itself should be excluded.
	if _, ok := byName["R"]; ok {
		t.Error("'R' runtime should not be included as a package")
	}
	for _, p := range pkgs {
		if !p.Direct {
			t.Errorf("package %q should be Direct=true in DESCRIPTION fallback", p.Name)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no R lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `library(httr)
library(processx)

fetch_data <- function(url) {
  GET(url)
}

run_cmd <- function(cmd) {
  system(cmd)
}

get_secret <- function() {
  Sys.getenv("SECRET_KEY")
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.R"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "exec", "env"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `add <- function(a, b) {
  a + b
}

greet <- function(name) {
  paste("Hello,", name)
}
`
	if err := os.WriteFile(filepath.Join(dir, "utils.R"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter integration test
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := Adapter{}
	if a.Name() != "r" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "r")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	lockContent := `{
  "R": { "Version": "4.3.2" },
  "Packages": {
    "httr": {
      "Package": "httr",
      "Version": "1.4.7",
      "Requirements": ["curl"]
    },
    "curl": {
      "Package": "curl",
      "Version": "5.2.0",
      "Requirements": []
    }
  }
}`
	descContent := `Package: myproject
Imports:
    httr (>= 1.4.0)
`
	if err := os.WriteFile(filepath.Join(dir, "renv.lock"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "DESCRIPTION"), []byte(descContent), 0o600); err != nil {
		t.Fatal(err)
	}

	a := Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules, got %d", len(g.Modules))
	}
	if _, ok := g.Packages["httr"]; !ok {
		t.Error("expected 'httr' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseRenvLock(f *testing.F) {
	f.Add([]byte(`{"R":{"Version":"4.3.2"},"Packages":{"httr":{"Package":"httr","Version":"1.4.7","Requirements":["curl"]}}}`))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("not json at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "renv.lock"), data, 0o600); err != nil {
			return
		}
		loadRenvLock(dir) //nolint:errcheck
	})
}
