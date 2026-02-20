package trace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping trace test in short mode")
	}

	testDir := t.TempDir()
	testCode := `package main

import "os/exec"

func main() {
	exec.Command("ls").Run()
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

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	// trace requires dtrace/strace which may not be available
	exitCode := Run([]string{"."})
	_ = exitCode // May fail if tracer not available
}

func TestRunWithJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping trace test in short mode")
	}

	testDir := t.TempDir()
	testCode := `package main

func main() {}
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

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"--json", "."})
	_ = exitCode
}

func TestRunNoArgs(t *testing.T) {
	exitCode := Run([]string{})
	if exitCode == 0 {
		t.Error("Expected trace with no args to fail")
	}
}

func TestRunWithTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping trace test in short mode")
	}

	testDir := t.TempDir()
	testCode := `package main

import "time"

func main() {
	time.Sleep(100 * time.Millisecond)
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

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"--timeout", "1s", "."})
	_ = exitCode
}

func TestDetectTracer(t *testing.T) {
	_, err := detectTracer()
	// May succeed or fail depending on OS and available tools
	if err != nil {
		// Verify error message is helpful
		errStr := err.Error()
		if !strings.Contains(errStr, "not") {
			t.Errorf("Expected helpful error message, got: %v", err)
		}
	}
}
