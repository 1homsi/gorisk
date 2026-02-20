package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	testDir := t.TempDir()
	mainCode := `package main

func main() {
	helper()
}

func helper() {}
`
	unusedCode := `package main

import "os/exec"

func unusedFunc() {
	exec.Command("ls").Run()
}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainCode), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "unused.go"), []byte(unusedCode), 0600); err != nil {
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

	exitCode := Run([]string{})
	if exitCode != 0 {
		t.Errorf("Expected reachability command to succeed, got exit code %d", exitCode)
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

	goMod := `module test
go 1.22
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"--json"})
	if exitCode != 0 {
		t.Errorf("Expected JSON reachability to succeed, got exit code %d", exitCode)
	}
}
