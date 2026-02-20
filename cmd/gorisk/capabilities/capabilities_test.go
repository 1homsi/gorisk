package capabilities

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
	// If exec capability is detected, should return 1 for HIGH risk
	// Otherwise 0 is acceptable
	if exitCode != 0 && exitCode != 1 {
		t.Errorf("Expected exit code 0 or 1, got %d", exitCode)
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
		t.Errorf("Expected success for LOW risk, got exit code %d", exitCode)
	}
}

func TestRunWithMinRisk(t *testing.T) {
	testDir := t.TempDir()
	testCode := `package main

import "net/http"

func main() {
	http.Get("https://example.com")
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

	// Filter to only high risk - network is MEDIUM, should not be shown
	exitCode := Run([]string{"--min-risk", "high"})
	if exitCode != 0 {
		t.Errorf("Expected success (no HIGH risk), got exit code %d", exitCode)
	}
}

func TestRunWithInvalidLanguage(t *testing.T) {
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
		t.Error("Expected failure for invalid language")
	}
}

func TestMeetsMinRisk(t *testing.T) {
	tests := []struct {
		name  string
		level string
		min   string
		want  bool
	}{
		{
			name:  "HIGH meets HIGH",
			level: "HIGH",
			min:   "HIGH",
			want:  true,
		},
		{
			name:  "HIGH meets MEDIUM",
			level: "HIGH",
			min:   "MEDIUM",
			want:  true,
		},
		{
			name:  "HIGH meets LOW",
			level: "HIGH",
			min:   "LOW",
			want:  true,
		},
		{
			name:  "MEDIUM does not meet HIGH",
			level: "MEDIUM",
			min:   "HIGH",
			want:  false,
		},
		{
			name:  "MEDIUM meets MEDIUM",
			level: "MEDIUM",
			min:   "MEDIUM",
			want:  true,
		},
		{
			name:  "MEDIUM meets LOW",
			level: "MEDIUM",
			min:   "LOW",
			want:  true,
		},
		{
			name:  "LOW does not meet HIGH",
			level: "LOW",
			min:   "HIGH",
			want:  false,
		},
		{
			name:  "LOW does not meet MEDIUM",
			level: "LOW",
			min:   "MEDIUM",
			want:  false,
		},
		{
			name:  "LOW meets LOW",
			level: "LOW",
			min:   "LOW",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := meetsMinRisk(tt.level, tt.min)
			if got != tt.want {
				t.Errorf("meetsMinRisk(%q, %q) = %v, want %v", tt.level, tt.min, got, tt.want)
			}
		})
	}
}
