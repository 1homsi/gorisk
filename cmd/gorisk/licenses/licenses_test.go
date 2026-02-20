package licenses

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
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

	exitCode := Run([]string{})
	if exitCode != 0 {
		t.Errorf("Expected licenses command to succeed, got exit code %d", exitCode)
	}
}

func TestRunWithJSON(t *testing.T) {
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

	exitCode := Run([]string{"--json"})
	if exitCode != 0 {
		t.Errorf("Expected JSON licenses to succeed, got exit code %d", exitCode)
	}
}
