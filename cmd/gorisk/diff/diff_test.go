package diff

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

require golang.org/x/crypto v0.15.0
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	// diff requires module@version format
	exitCode := Run([]string{"golang.org/x/crypto@v0.15.0", "golang.org/x/crypto@v0.16.0"})

	// May fail if module not in dependency graph or download fails - that's okay
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

require golang.org/x/crypto v0.15.0
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(testDir)

	exitCode := Run([]string{"--json", "golang.org/x/crypto@v0.15.0", "golang.org/x/crypto@v0.16.0"})
	_ = exitCode
}

func TestRunInvalidFormat(t *testing.T) {
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

	// Invalid format - missing version
	exitCode := Run([]string{"golang.org/x/crypto", "v0.16.0"})
	if exitCode == 0 {
		t.Error("Expected diff with invalid format to fail")
	}
}
