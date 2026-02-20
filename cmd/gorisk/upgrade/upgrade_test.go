package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
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

require golang.org/x/crypto v0.15.0
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	// upgrade shows available updates - may have none
	exitCode := Run([]string{})
	_ = exitCode
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
	_ = exitCode
}

func TestRunInvalidLanguage(t *testing.T) {
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

	exitCode := Run([]string{"--lang", "python"})
	if exitCode == 0 {
		t.Error("Expected upgrade with invalid language to fail")
	}
}
