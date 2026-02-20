package license

import (
	"testing"
)

func TestGithubOwnerRepo(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		wantOwner  string
		wantRepo   string
		wantOK     bool
	}{
		{
			name:       "valid github path",
			modulePath: "github.com/user/repo",
			wantOwner:  "user",
			wantRepo:   "repo",
			wantOK:     true,
		},
		{
			name:       "github path with subpackage",
			modulePath: "github.com/user/repo/subpkg",
			wantOwner:  "user",
			wantRepo:   "repo",
			wantOK:     true,
		},
		{
			name:       "non-github path",
			modulePath: "golang.org/x/tools",
			wantOwner:  "",
			wantRepo:   "",
			wantOK:     false,
		},
		{
			name:       "short path",
			modulePath: "github.com/user",
			wantOwner:  "",
			wantRepo:   "",
			wantOK:     false,
		},
		{
			name:       "empty path",
			modulePath: "",
			wantOwner:  "",
			wantRepo:   "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOwner, gotRepo, gotOK := githubOwnerRepo(tt.modulePath)

			if gotOwner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", gotOwner, tt.wantOwner)
			}
			if gotRepo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", gotRepo, tt.wantRepo)
			}
			if gotOK != tt.wantOK {
				t.Errorf("ok = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

func TestDetectNonGitHub(t *testing.T) {
	// Test with non-GitHub module
	report := Detect("golang.org/x/tools", "v0.1.0")

	if report.Module != "golang.org/x/tools" {
		t.Errorf("Module = %q, want %q", report.Module, "golang.org/x/tools")
	}
	if report.Version != "v0.1.0" {
		t.Errorf("Version = %q, want %q", report.Version, "v0.1.0")
	}
	if report.License != "unknown" {
		t.Errorf("License = %q, want %q", report.License, "unknown")
	}
	if !report.Risky {
		t.Error("Expected Risky = true for unknown license")
	}
	if report.Reason != "license not detected" {
		t.Errorf("Reason = %q, want %q", report.Reason, "license not detected")
	}
}

func TestRiskyLicenses(t *testing.T) {
	// Verify risky licenses map contains expected copyleft licenses
	expectedRisky := []string{
		"GPL-2.0",
		"GPL-3.0",
		"AGPL-3.0",
		"LGPL-2.1",
		"LGPL-3.0",
		"EUPL-1.1",
		"EUPL-1.2",
		"CCDL-1.0",
	}

	for _, license := range expectedRisky {
		if reason, found := riskyLicenses[license]; !found {
			t.Errorf("Expected risky license %q not found in map", license)
		} else if reason == "" {
			t.Errorf("Risky license %q has empty reason", license)
		}
	}
}

func TestGithubToken(t *testing.T) {
	// Save original value
	original := githubToken()
	defer func() {
		if original != "" {
			t.Setenv("GORISK_GITHUB_TOKEN", original)
		}
	}()

	// Test with no token
	t.Setenv("GORISK_GITHUB_TOKEN", "")
	if tok := githubToken(); tok != "" {
		t.Errorf("Expected empty token, got %q", tok)
	}

	// Test with token set
	t.Setenv("GORISK_GITHUB_TOKEN", "test-token")
	if tok := githubToken(); tok != "test-token" {
		t.Errorf("githubToken() = %q, want %q", tok, "test-token")
	}
}

func TestLicenseReport(t *testing.T) {
	// Test that LicenseReport struct can be created
	report := LicenseReport{
		Module:  "test",
		Version: "v1.0.0",
		License: "MIT",
		Risky:   false,
		Reason:  "",
	}

	if report.Module != "test" {
		t.Errorf("Module = %q, want %q", report.Module, "test")
	}
	if report.Risky {
		t.Error("Expected Risky = false for MIT license")
	}
}

// TestDetectIntegration is a basic integration test
// It will fail if GitHub API is unavailable, but tests the full flow
func TestDetectIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test with a well-known GitHub repo
	report := Detect("github.com/gorilla/mux", "v1.8.0")

	if report.Module != "github.com/gorilla/mux" {
		t.Errorf("Module = %q, want %q", report.Module, "github.com/gorilla/mux")
	}

	// gorilla/mux is BSD-3-Clause (non-risky)
	// Note: This test may fail if GitHub API changes or is unavailable
	t.Logf("Detected license: %s (Risky: %v, Reason: %s)",
		report.License, report.Risky, report.Reason)

	// At minimum, we should get some result
	if report.License == "" {
		t.Error("Expected non-empty license")
	}
}
