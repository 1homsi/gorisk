package explain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
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

	goMod := `module example.com/test
go 1.22
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"example.com/test"})
	if exitCode != 0 {
		t.Errorf("Expected explain command to succeed, got exit code %d", exitCode)
	}
}

func TestRunWithJSON(t *testing.T) {
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

	goMod := `module example.com/test
go 1.22
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"--json", "example.com/test"})
	if exitCode != 0 {
		t.Errorf("Expected JSON explain to succeed, got exit code %d", exitCode)
	}
}

func TestRunNoArgs(t *testing.T) {
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

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	// explain with no args shows all capabilities
	exitCode := Run([]string{})
	if exitCode != 0 {
		t.Errorf("Expected explain with no args to succeed, got exit code %d", exitCode)
	}
}
