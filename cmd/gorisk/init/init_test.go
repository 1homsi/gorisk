package initcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_WritesPolicy(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	code := Run([]string{})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	if _, err := os.Stat(filepath.Join(dir, policyFileName)); err != nil {
		t.Errorf("policy file not created: %v", err)
	}
}

func TestRun_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Create existing file
	if err := os.WriteFile(policyFileName, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without --force: should fail
	code := Run([]string{})
	if code != 1 {
		t.Errorf("expected exit 1 when file exists, got %d", code)
	}

	// With --force: should succeed
	code = Run([]string{"--force"})
	if code != 0 {
		t.Errorf("expected exit 0 with --force, got %d", code)
	}
}

func TestRun_Stdout(t *testing.T) {
	// Capture stdout by redirecting
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	code := Run([]string{"--stdout"})

	w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	os.Stdout = origStdout

	if code != 0 {
		t.Fatalf("expected exit 0 with --stdout, got %d", code)
	}
	if n == 0 {
		t.Error("expected output to stdout, got nothing")
	}
}

func TestRun_WithHook_NoGitRepo(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// No .git directory — should warn but not fail
	code := Run([]string{"--with-hook"})
	if code != 0 {
		t.Errorf("expected exit 0 even without .git, got %d", code)
	}
}

func TestRun_WithHook_GitRepo(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Create a fake .git/hooks directory
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}

	code := Run([]string{"--with-hook"})
	if code != 0 {
		t.Fatalf("expected exit 0 with .git/hooks present, got %d", code)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("pre-commit hook not created: %v", err)
	}

	// Check executable bit (0755)
	if info.Mode().Perm() != 0o755 {
		t.Errorf("expected hook permissions 0755, got %04o", info.Mode().Perm())
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != preCommitHookContent {
		t.Errorf("hook content mismatch:\ngot:  %q\nwant: %q", string(content), preCommitHookContent)
	}
}
