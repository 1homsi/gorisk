package viz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTestDir(t *testing.T) string {
	t.Helper()
	testDir := t.TempDir()
	testCode := `package main

import "crypto/sha256"

func main() {
	sha256.New()
}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(testCode), 0600); err != nil {
		t.Fatal(err)
	}

	goMod := `module test
go 1.22
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}
	return testDir
}

func TestRun(t *testing.T) {
	testDir := setupTestDir(t)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{})
	if exitCode != 0 {
		t.Errorf("Expected viz command to succeed, got exit code %d", exitCode)
	}
}

func TestRun_FormatHTML(t *testing.T) {
	testDir := setupTestDir(t)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	exitCode := Run([]string{"--format", "html"})

	w.Close()
	os.Stdout = origStdout

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(output, "<!DOCTYPE html>") && !strings.Contains(output, "<html") {
		t.Errorf("html format should produce HTML output, got: %s", output[:min(len(output), 200)])
	}
}

func TestRun_FormatJSON(t *testing.T) {
	testDir := setupTestDir(t)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	exitCode := Run([]string{"--format", "json"})

	w.Close()
	os.Stdout = origStdout

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	// Should be valid JSON with nodes and links keys
	if !strings.Contains(output, `"nodes"`) || !strings.Contains(output, `"links"`) {
		t.Errorf("json format should contain nodes and links, got: %s", output[:min(len(output), 200)])
	}
}

func TestRun_FormatDOT(t *testing.T) {
	testDir := setupTestDir(t)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	exitCode := Run([]string{"--format", "dot"})

	w.Close()
	os.Stdout = origStdout

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(output, "digraph {") {
		t.Errorf("dot format should start with digraph {, got: %s", output[:min(len(output), 200)])
	}
}

func TestRun_FormatInvalid(t *testing.T) {
	testDir := setupTestDir(t)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"--format", "xml"})
	if exitCode != 2 {
		t.Errorf("expected exit 2 for invalid format, got %d", exitCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
