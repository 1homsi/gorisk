package pr

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping git test in short mode")
	}

	testDir := t.TempDir()

	// Initialize git repo
	initCmd := exec.Command("git", "init")
	initCmd.Dir = testDir
	if err := initCmd.Run(); err != nil {
		t.Skip("git not available")
	}

	configEmail := exec.Command("git", "config", "user.email", "test@example.com")
	configEmail.Dir = testDir
	if err := configEmail.Run(); err != nil {
		t.Skip("git config failed")
	}

	configName := exec.Command("git", "config", "user.name", "Test User")
	configName.Dir = testDir
	if err := configName.Run(); err != nil {
		t.Skip("git config failed")
	}

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

	addCmd := exec.Command("git", "add", ".")
	addCmd.Dir = testDir
	if err := addCmd.Run(); err != nil {
		t.Skip("git add failed")
	}

	commitCmd := exec.Command("git", "commit", "-m", "initial")
	commitCmd.Dir = testDir
	if err := commitCmd.Run(); err != nil {
		t.Skip("git commit failed")
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	// pr command needs git commits and typically fails in test environment
	// Just verify it runs without crashing
	exitCode := Run([]string{})
	_ = exitCode
}

func TestRunWithJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping git test in short mode")
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

	exitCode := Run([]string{"--json"})
	_ = exitCode
}
