package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitAt(t *testing.T) {
	tests := []struct {
		input     string
		wantLeft  string
		wantRight string
		wantOK    bool
	}{
		{"golang.org/x/crypto@v0.15.0", "golang.org/x/crypto", "v0.15.0", true},
		{"github.com/foo/bar@v1.2.3", "github.com/foo/bar", "v1.2.3", true},
		{"noversion", "", "", false},
		{"module@v1@v2", "module@v1", "v2", true}, // LastIndex picks rightmost @
	}
	for _, tt := range tests {
		left, right, ok := splitAt(tt.input)
		if ok != tt.wantOK || left != tt.wantLeft || right != tt.wantRight {
			t.Errorf("splitAt(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.input, left, right, ok, tt.wantLeft, tt.wantRight, tt.wantOK)
		}
	}
}

func TestRunNoArgs(t *testing.T) {
	testDir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{})
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for no args, got %d", exitCode)
	}
}

func TestRunMissingVersion(t *testing.T) {
	testDir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"golang.org/x/crypto"}) // no @version
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for missing @version, got %d", exitCode)
	}
}

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
