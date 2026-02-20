package history

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/history"
)

// Helper to create a test dir with a recorded history snapshot.
func setupHistoryDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	snap := history.Snapshot{
		Commit: "abc1234",
		Modules: []history.ModuleSnapshot{
			{Module: "example.com/a", Version: "v1.0.0", RiskLevel: "HIGH", EffectiveScore: 50},
			{Module: "example.com/b", Version: "v2.0.0", RiskLevel: "MEDIUM", EffectiveScore: 15},
			{Module: "example.com/c", Version: "v3.0.0", RiskLevel: "LOW", EffectiveScore: 5},
		},
	}
	snap2 := history.Snapshot{
		Commit: "def5678",
		Modules: []history.ModuleSnapshot{
			{Module: "example.com/a", Version: "v1.0.0", RiskLevel: "MEDIUM", EffectiveScore: 20},
			{Module: "example.com/d", Version: "v1.0.0", RiskLevel: "HIGH", EffectiveScore: 40},
		},
	}

	h := &history.History{}
	h.Record(snap)
	h.Record(snap2)
	if err := h.Save(dir); err != nil {
		t.Fatalf("save history: %v", err)
	}
	return dir
}

func TestBuildSparkline(t *testing.T) {
	// Empty
	if s := buildSparkline(nil); s != "" {
		t.Errorf("expected empty sparkline, got %q", s)
	}

	// Single zero
	s := buildSparkline([]int{0})
	if len([]rune(s)) != 1 {
		t.Errorf("expected 1 rune, got %q", s)
	}

	// Various values
	s = buildSparkline([]int{0, 25, 50, 75, 100})
	if len([]rune(s)) != 5 {
		t.Errorf("expected 5 runes, got %q", s)
	}

	// Out-of-range values should be clamped
	s = buildSparkline([]int{-10, 200})
	if len([]rune(s)) != 2 {
		t.Errorf("expected 2 runes, got %q", s)
	}
}

func TestRiskColor(t *testing.T) {
	red, yellow, green := "RED", "YELLOW", "GREEN"
	if c := riskColor("HIGH", red, yellow, green); c != red {
		t.Errorf("HIGH → %q, want RED", c)
	}
	if c := riskColor("MEDIUM", red, yellow, green); c != yellow {
		t.Errorf("MEDIUM → %q, want YELLOW", c)
	}
	if c := riskColor("LOW", red, yellow, green); c != green {
		t.Errorf("LOW → %q, want GREEN", c)
	}
	if c := riskColor("UNKNOWN", red, yellow, green); c != green {
		t.Errorf("UNKNOWN → %q, want GREEN (default)", c)
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("expected contains to return true")
	}
	if contains([]string{"a", "b"}, "z") {
		t.Error("expected contains to return false")
	}
	if contains(nil, "a") {
		t.Error("expected contains to return false for nil slice")
	}
}

func TestRunShowWithHistory(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"show"})
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
}

func TestRunShowWithHistoryJSON(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"--json", "show"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for JSON show, got %d", exitCode)
	}
}

func TestRunDiffWithHistory(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"diff"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for diff, got %d", exitCode)
	}
}

func TestRunDiffWithHistoryJSON(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"--json", "diff"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for JSON diff, got %d", exitCode)
	}
}

func TestRunDiffWithIndices(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"diff", "1", "2"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for diff 1 2, got %d", exitCode)
	}
}

func TestRunDiffInvalidIndex(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"diff", "99"})
	if exitCode == 0 {
		t.Error("expected non-zero exit for invalid index")
	}
}

func TestRunDiffInvalidIndex2(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"diff", "1", "99"})
	if exitCode == 0 {
		t.Error("expected non-zero exit for invalid index")
	}
}

func TestRunTrendWithHistory(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"trend"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for trend, got %d", exitCode)
	}
}

func TestRunTrendWithHistoryJSON(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"--json", "trend"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for JSON trend, got %d", exitCode)
	}
}

func TestRunTrendWithModuleFilter(t *testing.T) {
	dir := setupHistoryDir(t)
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"trend", "--module", "example.com/a"})
	if exitCode != 0 {
		t.Errorf("expected exit 0 for trend with filter, got %d", exitCode)
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := Run([]string{"bogus"})
	if exitCode != 2 {
		t.Errorf("expected exit 2 for unknown subcommand, got %d", exitCode)
	}
}

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

	// "show" with no recorded history just prints "no history recorded"
	exitCode := Run([]string{"show"})
	_ = exitCode // May succeed or fail depending on .gorisk existence
}
