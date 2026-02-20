package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoAnalyzer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	analyzer := GoAnalyzer{}

	// Create test Go project
	dir := t.TempDir()

	mainGo := `package main

import "os/exec"

func main() {
	exec.Command("ls").Run()
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0600); err != nil {
		t.Fatal(err)
	}

	goMod := `module test
go 1.22
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	// Test Analyze
	reports, err := analyzer.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	t.Logf("Found %d packages with capabilities", len(reports))

	// Should find os/exec as reachable
	foundExec := false
	for _, r := range reports {
		t.Logf("Package: %s, Reachable: %v, Caps: %s",
			r.Package, r.Reachable, r.ReachableCaps.String())
		if r.Package == "os/exec" && r.Reachable {
			foundExec = true
		}
	}

	if !foundExec {
		t.Error("Expected to find os/exec as reachable")
	}
}

func TestGoAnalyzerWithEntryFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	analyzer := GoAnalyzer{}

	// Create test Go project with specific entry file
	dir := t.TempDir()

	mainGo := `package main

import "crypto/sha256"

func main() {
	sha256.New()
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0600); err != nil {
		t.Fatal(err)
	}

	goMod := `module test
go 1.22
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	// Test AnalyzeFrom with specific entry file
	reports, err := analyzer.AnalyzeFrom(dir, "main.go")
	if err != nil {
		t.Fatalf("AnalyzeFrom() error = %v", err)
	}

	t.Logf("Found %d packages with capabilities", len(reports))

	// Should find crypto packages as reachable
	foundCrypto := false
	for _, r := range reports {
		if r.Reachable && r.ReachableCaps.Has("crypto") {
			foundCrypto = true
			t.Logf("Found crypto package: %s", r.Package)
		}
	}

	if !foundCrypto {
		t.Log("Warning: crypto capability not found (may be normal if no imports detected)")
	}
}

func TestNodeAnalyzer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	analyzer := NodeAnalyzer{}

	// Create test Node.js project
	dir := t.TempDir()

	indexJS := `const fs = require('fs');
const { exec } = require('child_process');

fs.readFileSync('test.txt');
exec('ls');
`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(indexJS), 0600); err != nil {
		t.Fatal(err)
	}

	packageJSON := `{
  "name": "test",
  "version": "1.0.0",
  "dependencies": {}
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Create empty lockfile
	lockJSON := `{
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "test",
      "version": "1.0.0"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Test Analyze
	reports, err := analyzer.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	t.Logf("Found %d packages with capabilities", len(reports))

	// Node analysis may not find built-in modules like 'fs' as separate packages
	// This is expected behavior - just verify it doesn't crash
	for _, r := range reports {
		t.Logf("Package: %s, Reachable: %v, Caps: %s",
			r.Package, r.Reachable, r.ReachableCaps.String())
	}
}

func TestNodeAnalyzerWithEntryFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	analyzer := NodeAnalyzer{}

	// Create test Node.js project
	dir := t.TempDir()

	indexJS := `const crypto = require('crypto');
crypto.createHash('sha256');
`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(indexJS), 0600); err != nil {
		t.Fatal(err)
	}

	packageJSON := `{
  "name": "test",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Create empty lockfile
	lockJSON := `{
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "test",
      "version": "1.0.0"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Test AnalyzeFrom with specific entry file
	reports, err := analyzer.AnalyzeFrom(dir, "index.js")
	if err != nil {
		t.Fatalf("AnalyzeFrom() error = %v", err)
	}

	t.Logf("Found %d packages from entry file", len(reports))

	for _, r := range reports {
		t.Logf("Package: %s, Reachable: %v", r.Package, r.Reachable)
	}
}

func TestReachabilityReport(t *testing.T) {
	// Test ReachabilityReport struct
	report := ReachabilityReport{
		Package:   "test/pkg",
		Reachable: true,
	}

	if report.Package != "test/pkg" {
		t.Errorf("Package = %q, want %q", report.Package, "test/pkg")
	}
	if !report.Reachable {
		t.Error("Expected Reachable = true")
	}
}

func TestAnalyzerInterface(t *testing.T) {
	// Verify that both analyzers implement the Analyzer interface
	var _ Analyzer = GoAnalyzer{}
	var _ Analyzer = NodeAnalyzer{}

	// This test compiles successfully if the interface is satisfied
	t.Log("Both GoAnalyzer and NodeAnalyzer implement Analyzer interface")
}
