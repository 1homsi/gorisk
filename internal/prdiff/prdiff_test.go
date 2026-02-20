package prdiff

import (
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

func TestModuleDiff(t *testing.T) {
	diff := ModuleDiff{
		Module:       "github.com/foo/bar",
		OldVersion:   "v1.0.0",
		NewVersion:   "v2.0.0",
		CapEscalated: true,
	}

	if diff.Module != "github.com/foo/bar" {
		t.Errorf("Module = %q, want %q", diff.Module, "github.com/foo/bar")
	}
	if !diff.CapEscalated {
		t.Error("Expected CapEscalated = true")
	}
}

func TestPRDiffReport(t *testing.T) {
	caps := capability.CapabilitySet{}
	caps.Add(capability.CapExec)

	report := PRDiffReport{
		Added: []ModuleDiff{
			{
				Module:     "new/module",
				NewVersion: "v1.0.0",
				Caps:       caps,
			},
		},
		Removed: []string{"old/module"},
		Updated: []ModuleDiff{
			{
				Module:       "updated/module",
				OldVersion:   "v1.0.0",
				NewVersion:   "v2.0.0",
				CapEscalated: true,
			},
		},
	}

	if len(report.Added) != 1 {
		t.Errorf("Added len = %d, want 1", len(report.Added))
	}
	if len(report.Removed) != 1 {
		t.Errorf("Removed len = %d, want 1", len(report.Removed))
	}
	if len(report.Updated) != 1 {
		t.Errorf("Updated len = %d, want 1", len(report.Updated))
	}
	if report.Removed[0] != "old/module" {
		t.Errorf("Removed[0] = %q, want %q", report.Removed[0], "old/module")
	}
	if !report.Updated[0].CapEscalated {
		t.Error("Expected Updated[0].CapEscalated = true")
	}
}

func TestDifferInterface(t *testing.T) {
	// Verify that both differs implement the Differ interface
	var _ Differ = GoDiffer{}
	var _ Differ = NodeDiffer{}

	t.Log("Both GoDiffer and NodeDiffer implement Differ interface")
}

func TestPRDiffReportEmpty(t *testing.T) {
	report := PRDiffReport{}

	if report.Added != nil {
		t.Errorf("Empty report Added should be nil, got %v", report.Added)
	}
	if report.Removed != nil {
		t.Errorf("Empty report Removed should be nil, got %v", report.Removed)
	}
	if report.Updated != nil {
		t.Errorf("Empty report Updated should be nil, got %v", report.Updated)
	}
}

// ── parseComposerJSONDiff (PHP) ───────────────────────────────────────────────

func TestParseComposerJSONDiffAdded(t *testing.T) {
	diff := `diff --git a/composer.json b/composer.json
--- a/composer.json
+++ b/composer.json
@@ -5,6 +5,7 @@
     "require": {
+        "symfony/process": "^6.0",
         "guzzlehttp/guzzle": "^7.0"
     }
`
	report := parseComposerJSONDiff(diff)
	if len(report.Added) != 1 {
		t.Fatalf("expected 1 Added, got %d", len(report.Added))
	}
	if report.Added[0].Module != "symfony/process" {
		t.Errorf("Added[0].Module = %q, want symfony/process", report.Added[0].Module)
	}
}

func TestParseComposerJSONDiffRemoved(t *testing.T) {
	diff := `diff --git a/composer.json b/composer.json
--- a/composer.json
+++ b/composer.json
@@ -5,7 +5,6 @@
     "require": {
-        "firebase/php-jwt": "^5.0",
         "guzzlehttp/guzzle": "^7.0"
     }
`
	report := parseComposerJSONDiff(diff)
	if len(report.Removed) != 1 {
		t.Fatalf("expected 1 Removed, got %d", len(report.Removed))
	}
	if report.Removed[0] != "firebase/php-jwt" {
		t.Errorf("Removed[0] = %q, want firebase/php-jwt", report.Removed[0])
	}
}

func TestParseComposerJSONDiffUpdated(t *testing.T) {
	diff := `diff --git a/composer.json b/composer.json
--- a/composer.json
+++ b/composer.json
@@ -5,6 +5,6 @@
     "require": {
-        "guzzlehttp/guzzle": "^6.0",
+        "guzzlehttp/guzzle": "^7.0",
         "php": "^8.0"
     }
`
	report := parseComposerJSONDiff(diff)
	if len(report.Updated) != 1 {
		t.Fatalf("expected 1 Updated, got %d: %v", len(report.Updated), report.Updated)
	}
	if report.Updated[0].Module != "guzzlehttp/guzzle" {
		t.Errorf("Updated[0].Module = %q, want guzzlehttp/guzzle", report.Updated[0].Module)
	}
}

func TestParseComposerJSONDiffEmpty(t *testing.T) {
	report := parseComposerJSONDiff("")
	if len(report.Added)+len(report.Removed)+len(report.Updated) != 0 {
		t.Errorf("expected empty report for empty diff, got %+v", report)
	}
}

func TestParseComposerJSONDiffSkipsDiffHeaders(t *testing.T) {
	// Lines like "--- a/composer.json" and "+++ b/composer.json" must be skipped
	diff := `diff --git a/composer.json b/composer.json
--- a/composer.json
+++ b/composer.json
+        "monolog/monolog": "^3.0"
`
	report := parseComposerJSONDiff(diff)
	// "--- a/composer.json" and "+++ b/composer.json" should be skipped, only the dep line counts
	if len(report.Added) != 1 {
		t.Fatalf("expected 1 Added, got %d", len(report.Added))
	}
	if report.Added[0].Module != "monolog/monolog" {
		t.Errorf("Added module = %q, want monolog/monolog", report.Added[0].Module)
	}
}

// ── parseComposerDepLine (PHP) ────────────────────────────────────────────────

func TestParseComposerDepLine(t *testing.T) {
	tests := []struct {
		line    string
		name    string
		version string
		ok      bool
	}{
		{`"guzzlehttp/guzzle": "^7.0",`, "guzzlehttp/guzzle", "^7.0", true},
		{`"symfony/process": "^6.0"`, "symfony/process", "^6.0", true},
		{`  "aws/aws-sdk-php": "^3.0",`, "aws/aws-sdk-php", "^3.0", true},
		// No slash → not a vendor/package name
		{`"php": "^8.0"`, "", "", false},
		// Not a quoted key
		{`invalid line`, "", "", false},
		{``, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			n, v, ok := parseComposerDepLine(tt.line)
			if ok != tt.ok {
				t.Errorf("ok = %v, want %v", ok, tt.ok)
			}
			if ok {
				if n != tt.name {
					t.Errorf("name = %q, want %q", n, tt.name)
				}
				if v != tt.version {
					t.Errorf("version = %q, want %q", v, tt.version)
				}
			}
		})
	}
}

// ── PHPDiffer interface ────────────────────────────────────────────────────────

func TestPHPDifferImplementsInterface(t *testing.T) {
	var _ Differ = PHPDiffer{}
}

func TestModuleDiffWithCapabilities(t *testing.T) {
	caps := capability.CapabilitySet{}
	caps.Add(capability.CapExec)
	caps.Add(capability.CapNetwork)

	diff := ModuleDiff{
		Module:       "test/module",
		OldVersion:   "v1.0.0",
		NewVersion:   "v1.1.0",
		Caps:         caps,
		CapEscalated: false,
	}

	if !diff.Caps.Has("exec") {
		t.Error("Expected Caps to have 'exec'")
	}
	if !diff.Caps.Has("network") {
		t.Error("Expected Caps to have 'network'")
	}
	if diff.CapEscalated {
		t.Error("Expected CapEscalated = false")
	}
}

func TestParsePackageJSONDepLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{
			name:        "Valid dependency",
			line:        `    "express": "^4.17.1",`,
			wantName:    "express",
			wantVersion: "4.17.1", // Function strips ^
			wantOK:      true,
		},
		{
			name:        "Valid without comma",
			line:        `    "lodash": "4.17.21"`,
			wantName:    "lodash",
			wantVersion: "4.17.21",
			wantOK:      true,
		},
		{
			name:        "Scoped package",
			line:        `    "@types/node": "^14.0.0",`,
			wantName:    "@types/node",
			wantVersion: "14.0.0", // Function strips ^
			wantOK:      true,
		},
		{
			name:   "Invalid - no colon",
			line:   `    "invalid"`,
			wantOK: false,
		},
		{
			name:   "Invalid - not a dependency line",
			line:   `  "scripts": {`,
			wantOK: false,
		},
		{
			name:   "Empty line",
			line:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion, gotOK := parsePackageJSONDepLine(tt.line)
			if gotOK != tt.wantOK {
				t.Errorf("parsePackageJSONDepLine() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotOK {
				if gotName != tt.wantName {
					t.Errorf("parsePackageJSONDepLine() name = %v, want %v", gotName, tt.wantName)
				}
				if gotVersion != tt.wantVersion {
					t.Errorf("parsePackageJSONDepLine() version = %v, want %v", gotVersion, tt.wantVersion)
				}
			}
		})
	}
}
