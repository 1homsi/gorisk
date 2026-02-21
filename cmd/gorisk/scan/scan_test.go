package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/taint"
)

func TestBuildExceptions(t *testing.T) {
	allowExceptions := []PolicyException{
		{
			Package:      "test/pkg1",
			Capabilities: []string{"exec", "network"},
		},
		{
			Package: "test/pkg2",
			Taint:   []string{"network→exec", "env→exec"},
		},
	}

	exceptions, taintExceptions, stats := buildExceptions(allowExceptions)

	// Check capability exceptions
	if len(exceptions) != 1 {
		t.Errorf("expected 1 capability exception, got %d", len(exceptions))
	}
	if !exceptions["test/pkg1"]["exec"] {
		t.Error("expected exec capability exception for test/pkg1")
	}
	if !exceptions["test/pkg1"]["network"] {
		t.Error("expected network capability exception for test/pkg1")
	}

	// Check taint exceptions
	if len(taintExceptions) != 1 {
		t.Errorf("expected 1 taint exception package, got %d", len(taintExceptions))
	}
	if !taintExceptions["test/pkg2"]["network→exec"] {
		t.Error("expected network→exec taint exception for test/pkg2")
	}

	// Check stats
	if stats.Applied != 2 {
		t.Errorf("expected 2 applied exceptions, got %d", stats.Applied)
	}
	if stats.TaintSuppressed != 2 {
		t.Errorf("expected 2 taint suppressions, got %d", stats.TaintSuppressed)
	}
}

func TestBuildExceptionsExpired(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	allowExceptions := []PolicyException{
		{
			Package:      "test/pkg",
			Capabilities: []string{"exec"},
			Expires:      yesterday,
		},
	}

	exceptions, _, stats := buildExceptions(allowExceptions)

	// Expired exceptions should not be applied
	if len(exceptions) != 0 {
		t.Errorf("expected 0 applied exceptions for expired policy, got %d", len(exceptions))
	}

	if stats.Expired != 1 {
		t.Errorf("expected 1 expired exception, got %d", stats.Expired)
	}
}

func TestBuildExceptionsValidExpiry(t *testing.T) {
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	allowExceptions := []PolicyException{
		{
			Package:      "test/pkg",
			Capabilities: []string{"exec"},
			Expires:      tomorrow,
		},
	}

	exceptions, _, stats := buildExceptions(allowExceptions)

	// Non-expired exceptions should be applied
	if len(exceptions) != 1 {
		t.Errorf("expected 1 applied exception, got %d", len(exceptions))
	}

	if stats.Expired != 0 {
		t.Errorf("expected 0 expired exceptions, got %d", stats.Expired)
	}
}

func TestFilterTaintFindings(t *testing.T) {
	findings := []taint.TaintFinding{
		{
			Package: "test/pkg1",
			Source:  capability.CapNetwork,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
		{
			Package: "test/pkg1",
			Source:  capability.CapEnv,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
		{
			Package: "test/pkg2",
			Source:  capability.CapNetwork,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
	}

	// Suppress network→exec for test/pkg1
	taintExceptions := map[string]map[string]bool{
		"test/pkg1": {
			"network→exec": true,
		},
	}

	filtered := filterTaintFindings(findings, taintExceptions)

	// Should filter out the first finding (test/pkg1 network→exec)
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings after filtering, got %d", len(filtered))
	}

	// Verify the correct finding was filtered
	for _, f := range filtered {
		if f.Package == "test/pkg1" && f.Source == capability.CapNetwork && f.Sink == capability.CapExec {
			t.Error("expected network→exec for test/pkg1 to be filtered")
		}
	}

	// Verify env→exec for test/pkg1 is still present
	foundEnvExec := false
	for _, f := range filtered {
		if f.Package == "test/pkg1" && f.Source == capability.CapEnv && f.Sink == capability.CapExec {
			foundEnvExec = true
		}
	}
	if !foundEnvExec {
		t.Error("expected env→exec for test/pkg1 to remain")
	}
}

func TestFilterTaintFindingsNoExceptions(t *testing.T) {
	findings := []taint.TaintFinding{
		{
			Package: "test/pkg",
			Source:  capability.CapNetwork,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
	}

	filtered := filterTaintFindings(findings, nil)

	// No exceptions, all findings should remain
	if len(filtered) != len(findings) {
		t.Errorf("expected %d findings, got %d", len(findings), len(filtered))
	}
}

// ── fmtDur ───────────────────────────────────────────────────────────────────

func TestFmtDur(t *testing.T) {
	tests := []struct {
		d        time.Duration
		contains string
	}{
		{200 * time.Microsecond, "ms"}, // sub-ms → "X.XXms"
		{999 * time.Microsecond, "ms"}, // sub-ms → "X.XXms"
		{time.Millisecond, "s"},        // ≥1ms → seconds branch → "0.00s"
		{time.Second, "s"},
		{2500 * time.Millisecond, "s"},
	}
	for _, tt := range tests {
		got := fmtDur(tt.d)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("fmtDur(%v) = %q, want to contain %q", tt.d, got, tt.contains)
		}
	}
}

func TestFmtDurSubMs(t *testing.T) {
	got := fmtDur(500 * time.Microsecond)
	// Sub-millisecond: formatted as X.XXms
	if !strings.HasSuffix(got, "ms") {
		t.Errorf("fmtDur(500µs) = %q, want suffix ms", got)
	}
}

// ── writeExceptionSummary ─────────────────────────────────────────────────────

func TestWriteExceptionSummary(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	writeExceptionSummary(f, exceptionStats{
		Applied:         3,
		Expired:         1,
		TaintSuppressed: 2,
	})
	f.Close()

	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)
	if !strings.Contains(content, "Applied: 3") {
		t.Errorf("want 'Applied: 3', got: %s", content)
	}
	if !strings.Contains(content, "Taint flows suppressed: 2") {
		t.Errorf("want taint suppressed line, got: %s", content)
	}
	if !strings.Contains(content, "Expired (not applied): 1") {
		t.Errorf("want expired line, got: %s", content)
	}
}

func TestWriteExceptionSummaryZeroCounts(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	writeExceptionSummary(f, exceptionStats{Applied: 0})
	f.Close()

	got, _ := os.ReadFile(f.Name())
	content := string(got)
	// Zero counts for taint/expired/missing should not appear
	if strings.Contains(content, "Taint") {
		t.Errorf("unexpected Taint line for zero count: %s", content)
	}
	if strings.Contains(content, "Expired") {
		t.Errorf("unexpected Expired line for zero count: %s", content)
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

func TestRunBadLang(t *testing.T) {
	dir := t.TempDir()
	gomod := "module test\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--lang", "cobol"})
	if code == 0 {
		t.Error("expected non-zero exit for unknown language")
	}
}

func TestRunBadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	gomod := "module test\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--policy", "/nonexistent/policy.json"})
	if code == 0 {
		t.Error("expected non-zero exit for missing policy file")
	}
}

func TestRunInvalidPolicyJSON(t *testing.T) {
	dir := t.TempDir()
	gomod := "module test\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{invalid json`), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--policy", policyPath})
	if code == 0 {
		t.Error("expected non-zero exit for malformed policy JSON")
	}
}

func TestRunInvalidPolicyVersion(t *testing.T) {
	dir := t.TempDir()
	gomod := "module test\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"version": 99}`), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--policy", policyPath})
	if code == 0 {
		t.Error("expected non-zero exit for unsupported policy version")
	}
}

func TestRunInvalidFailOn(t *testing.T) {
	dir := t.TempDir()
	gomod := "module test\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"version":1,"fail_on":"critical"}`), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--policy", policyPath})
	if code == 0 {
		t.Error("expected non-zero exit for invalid fail_on value")
	}
}

func TestRunGoProjectPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--lang", "go"})
	if code != 0 {
		t.Errorf("Run() = %d, want 0 for clean project", code)
	}
}

func TestRunJSONOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--json", "--lang", "go"})
	if code != 0 {
		t.Errorf("Run(--json) = %d, want 0", code)
	}
}

func TestRunSARIFOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--sarif", "--lang", "go"})
	if code != 0 {
		t.Errorf("Run(--sarif) = %d, want 0", code)
	}
}

func TestRunWithExcludePackages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"version":1,"fail_on":"high","exclude_packages":["somelib/v2"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer os.Chdir(orig) //nolint:errcheck
	os.Chdir(dir)        //nolint:errcheck

	code := Run([]string{"--lang", "go", "--policy", policyPath})
	if code != 0 {
		t.Errorf("Run with policy = %d, want 0", code)
	}
}
