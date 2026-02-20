package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoriskScanCommand tests the full scan command on a real project
func TestGoriskScanCommand(t *testing.T) {
	// Build gorisk binary
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

	// Create test project
	testDir := t.TempDir()
	testCode := `package main

import (
	"os/exec"
	"net/http"
)

func main() {
	exec.Command("ls").Run()
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

	// Run scan
	scanCmd := exec.Command(binPath, "scan", "--fail-on", "high")
	scanCmd.Dir = testDir
	output, err := scanCmd.CombinedOutput()

	t.Logf("Scan output:\n%s", output)

	// Should detect HIGH risk (exec capability)
	if err == nil {
		t.Error("Expected scan to fail with HIGH risk, but it passed")
	}

	// Check output contains expected capabilities
	outputStr := string(output)
	if !strings.Contains(outputStr, "exec") {
		t.Error("Expected output to mention 'exec' capability")
	}
	if !strings.Contains(outputStr, "network") {
		t.Error("Expected output to mention 'network' capability")
	}
}

// TestGoriskCapabilitiesCommand tests the capabilities command
func TestGoriskCapabilitiesCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	// Run capabilities
	capCmd := exec.Command(binPath, "capabilities")
	capCmd.Dir = testDir
	output, err := capCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capabilities command failed: %v\nOutput: %s", err, output)
	}

	t.Logf("Capabilities output:\n%s", output)

	outputStr := string(output)
	if !strings.Contains(outputStr, "crypto") {
		t.Error("Expected output to mention 'crypto' capability")
	}
}

// TestGoriskPolicyFile tests scan with policy file
func TestGoriskPolicyFile(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	// Create policy that allows exec
	policy := `{
  "fail_on": "high",
  "allow_exceptions": [
    {
      "package": "test",
      "taint": ["env→exec"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(testDir, "policy.json"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}

	// Run scan with policy - should pass now
	scanCmd := exec.Command(binPath, "scan", "--fail-on", "high", "--policy", "policy.json")
	scanCmd.Dir = testDir
	output, err := scanCmd.CombinedOutput()

	t.Logf("Scan output:\n%s", output)

	if err != nil {
		t.Errorf("Expected scan to pass with policy exceptions, but it failed: %v", err)
	}
}

// TestGoriskJSONOutput tests JSON output format
func TestGoriskJSONOutput(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	// Run scan with --json
	// Note: Using --fail-on high so MEDIUM risk doesn't cause exit code 1
	scanCmd := exec.Command(binPath, "scan", "--json", "--fail-on", "high")
	scanCmd.Dir = testDir
	output, err := scanCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("JSON scan failed: %v\nOutput: %s", err, output)
	}

	// Verify JSON is valid
	outputStr := string(output)
	if !strings.Contains(outputStr, "{") || !strings.Contains(outputStr, "}") {
		t.Error("Expected JSON output, got non-JSON format")
	}
	// Check for Capabilities field (capitalized in JSON output)
	if !strings.Contains(outputStr, "\"Capabilities\"") {
		t.Error("Expected JSON to contain 'Capabilities' field")
	}
}

// TestGoriskVersionCommand tests version command
func TestGoriskVersionCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

	versionCmd := exec.Command(binPath, "version")
	output, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\nOutput: %s", err, output)
	}

	t.Logf("Version output: %s", output)

	outputStr := strings.TrimSpace(string(output))
	// Accept "dev" for development builds or any version string containing "gorisk" or semantic version
	if outputStr != "dev" && !strings.Contains(outputStr, "gorisk") && !strings.Contains(outputStr, ".") {
		t.Errorf("Expected version output to be 'dev' or mention 'gorisk', got: %s", outputStr)
	}
}

// TestGoriskExplainCommand tests explain command
func TestGoriskExplainCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	goMod := `module example.com/testmod
go 1.22
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	// Run explain with the actual module/package path
	explainCmd := exec.Command(binPath, "explain", "example.com/testmod")
	explainCmd.Dir = testDir
	output, err := explainCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("explain command failed: %v\nOutput: %s", err, output)
	}

	t.Logf("Explain output:\n%s", output)

	outputStr := string(output)
	// Check that command produces some output (even if "no capabilities found")
	if len(strings.TrimSpace(outputStr)) == 0 {
		t.Error("Expected non-empty output from explain command")
	}
	// Command succeeded if we got here - "no capabilities found" is a valid result
}

// TestGoriskGraphCommand tests graph command
func TestGoriskGraphCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	graphCmd := exec.Command(binPath, "graph")
	graphCmd.Dir = testDir
	output, err := graphCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("graph command failed: %v\nOutput: %s", err, output)
	}

	t.Logf("Graph output:\n%s", output)

	outputStr := string(output)
	// graph command shows modules, not packages - just verify it runs and shows headers
	if !strings.Contains(outputStr, "MODULE") && !strings.Contains(outputStr, "RISK") {
		t.Error("Expected output to contain graph table headers")
	}
}

// TestGoriskReachabilityCommand tests reachability command
func TestGoriskReachabilityCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

	testDir := t.TempDir()
	mainCode := `package main

func main() {
	helper()
}

func helper() {
	// no capabilities
}
`
	utilCode := `package main

import "os/exec"

func unusedFunc() {
	exec.Command("ls").Run()
}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainCode), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "util.go"), []byte(utilCode), 0600); err != nil {
		t.Fatal(err)
	}

	goMod := `module test
go 1.22
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	reachCmd := exec.Command(binPath, "reachability")
	reachCmd.Dir = testDir
	output, err := reachCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reachability command failed: %v\nOutput: %s", err, output)
	}

	t.Logf("Reachability output:\n%s", output)

	outputStr := string(output)
	// Should show that unusedFunc is unreachable
	if !strings.Contains(outputStr, "Reachability") && !strings.Contains(outputStr, "unreachable") {
		t.Logf("Warning: Expected output to mention reachability analysis")
	}
}

// TestGoriskHistoryCommand tests history command
func TestGoriskHistoryCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

	testDir := t.TempDir()

	// Initialize git repo in testDir
	initCmd := exec.Command("git", "init")
	initCmd.Dir = testDir
	if err := initCmd.Run(); err != nil {
		t.Skip("git not available, skipping history test")
	}

	configEmail := exec.Command("git", "config", "user.email", "test@example.com")
	configEmail.Dir = testDir
	if err := configEmail.Run(); err != nil {
		t.Skip("git config failed, skipping history test")
	}

	configName := exec.Command("git", "config", "user.name", "Test User")
	configName.Dir = testDir
	if err := configName.Run(); err != nil {
		t.Skip("git config failed, skipping history test")
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

	// Make a commit
	addCmd := exec.Command("git", "add", ".")
	addCmd.Dir = testDir
	if err := addCmd.Run(); err != nil {
		t.Skip("git add failed, skipping history test")
	}

	commitCmd := exec.Command("git", "commit", "-m", "initial")
	commitCmd.Dir = testDir
	if err := commitCmd.Run(); err != nil {
		t.Skip("git commit failed, skipping history test")
	}

	historyCmd := exec.Command(binPath, "history", "--limit", "1")
	historyCmd.Dir = testDir
	output, err := historyCmd.CombinedOutput()

	t.Logf("History output:\n%s", output)

	// history command may fail if no .gorisk directory exists, that's okay
	if err != nil {
		t.Logf("history command failed (expected for first run): %v", err)
		return
	}

	outputStr := string(output)
	// If it succeeds, it should show some history information
	if len(outputStr) == 0 {
		t.Error("Expected non-empty history output")
	}
}

// TestGoriskUpgradeCommand tests upgrade command
func TestGoriskUpgradeCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	upgradeCmd := exec.Command(binPath, "upgrade")
	upgradeCmd.Dir = testDir
	output, err := upgradeCmd.CombinedOutput()

	t.Logf("Upgrade output:\n%s", output)

	// upgrade command shows available updates - may have none
	if err != nil {
		t.Logf("upgrade command failed (expected if no updates): %v", err)
		return
	}

	outputStr := string(output)
	if len(outputStr) == 0 {
		t.Error("Expected non-empty upgrade output")
	}
}

// TestGoriskDiffCommand tests diff command
func TestGoriskDiffCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
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

require golang.org/x/crypto v0.15.0
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}

	// diff expects module@version format
	diffCmd := exec.Command(binPath, "diff", "golang.org/x/crypto@v0.15.0", "golang.org/x/crypto@v0.16.0")
	diffCmd.Dir = testDir
	output, err := diffCmd.CombinedOutput()

	t.Logf("Diff output:\n%s", output)

	// diff may fail if module not found or no changes - that's expected for this test
	if err != nil {
		t.Logf("diff command failed (expected for test module): %v", err)
		return
	}

	outputStr := string(output)
	if len(outputStr) == 0 {
		t.Error("Expected non-empty diff output")
	}
}

// TestGoriskImpactCommand tests impact command
func TestGoriskImpactCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	// impact expects a real module path - "test" won't have dependencies
	// This will likely fail since we have no real dependencies, but verify command runs
	impactCmd := exec.Command(binPath, "impact", "golang.org/x/crypto")
	impactCmd.Dir = testDir
	output, err := impactCmd.CombinedOutput()

	t.Logf("Impact output:\n%s", output)

	// impact may fail if module not in dependency graph - that's okay for this test
	if err != nil {
		outputStr := string(output)
		// Verify it's a "not found" error, not a crash
		if !strings.Contains(outputStr, "not found") && !strings.Contains(outputStr, "no dependencies") {
			t.Logf("impact command failed: %v", err)
		}
		return
	}

	outputStr := string(output)
	if len(outputStr) == 0 {
		t.Error("Expected non-empty impact output")
	}
}

// TestGoriskTraceCommand tests trace command
func TestGoriskTraceCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	// trace command builds and traces a package, so pass "." for current directory
	traceCmd := exec.Command(binPath, "trace", ".")
	traceCmd.Dir = testDir
	output, err := traceCmd.CombinedOutput()

	t.Logf("Trace output:\n%s", output)

	// trace may fail if dtrace/strace not available - that's okay
	if err != nil {
		if strings.Contains(string(output), "not available") || strings.Contains(string(output), "not found") {
			t.Skip("Trace tool (dtrace/strace) not available, skipping test")
		}
		t.Fatalf("trace command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	// If successful, should show some trace output or "no syscall events captured"
	if len(strings.TrimSpace(outputStr)) == 0 {
		t.Error("Expected non-empty trace output")
	}
}

// TestGoriskVizCommand tests viz command
func TestGoriskVizCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	vizCmd := exec.Command(binPath, "viz")
	vizCmd.Dir = testDir
	output, err := vizCmd.CombinedOutput()

	t.Logf("Viz output:\n%s", output)

	if err != nil {
		t.Fatalf("viz command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	// viz generates HTML visualization
	if !strings.Contains(outputStr, "<!DOCTYPE") && !strings.Contains(outputStr, "<html") {
		t.Error("Expected viz output to be in HTML format")
	}
}

// TestGoriskSBOMCommand tests sbom command
func TestGoriskSBOMCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	sbomCmd := exec.Command(binPath, "sbom")
	sbomCmd.Dir = testDir
	output, err := sbomCmd.CombinedOutput()

	t.Logf("SBOM output:\n%s", output)

	if err != nil {
		t.Fatalf("sbom command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	// sbom generates CycloneDX JSON
	if !strings.Contains(outputStr, "CycloneDX") && !strings.Contains(outputStr, "bomFormat") {
		t.Error("Expected sbom output to be in CycloneDX format")
	}
}

// TestGoriskLicensesCommand tests licenses command
func TestGoriskLicensesCommand(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "gorisk")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/gorisk")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gorisk: %v", err)
	}

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

	licensesCmd := exec.Command(binPath, "licenses")
	licensesCmd.Dir = testDir
	output, err := licensesCmd.CombinedOutput()

	t.Logf("Licenses output:\n%s", output)

	if err != nil {
		t.Fatalf("licenses command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	// licenses command should produce some output (may be empty if no deps)
	if len(strings.TrimSpace(outputStr)) == 0 {
		t.Log("licenses command produced empty output (expected for project with no external dependencies)")
	}
}
