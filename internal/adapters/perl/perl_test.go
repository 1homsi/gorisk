package perl

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadCpanfileSnapshot(t *testing.T) {
	dir := t.TempDir()

	snapshotContent := `# carton snapshot format: version 1.0
DISTRIBUTIONS
  Carp-1.50
    pathname: C/CG/CGMORTON/Carp-1.50.tar.gz
    provides:
      Carp 1.50
      Carp::Heavy 1.50
    requirements:
      perl 5.008001
  libwww-perl-6.67
    pathname: O/OA/OALDERS/libwww-perl-6.67.tar.gz
    provides:
      LWP::UserAgent 6.67
    requirements:
      Carp 0
`
	cpanfileContent := `requires 'LWP::UserAgent', '6.0';
requires 'Carp';
`
	if err := os.WriteFile(filepath.Join(dir, "cpanfile.snapshot"), []byte(snapshotContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpanfile"), []byte(cpanfileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]PerlPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["Carp"]; !ok {
		t.Error("expected 'Carp' in packages")
	}
	if _, ok := byName["LWP::UserAgent"]; !ok {
		t.Error("expected 'LWP::UserAgent' in packages")
	}
	if byName["LWP::UserAgent"].Version != "6.67" {
		t.Errorf("LWP::UserAgent version: got %q, want %q", byName["LWP::UserAgent"].Version, "6.67")
	}
	// LWP::UserAgent is in cpanfile, so it should be direct.
	if !byName["LWP::UserAgent"].Direct {
		t.Error("LWP::UserAgent should be a direct dep (listed in cpanfile)")
	}
}

func TestLoadCpanfile(t *testing.T) {
	dir := t.TempDir()
	content := `requires 'LWP::UserAgent', '6.0';
requires 'Moose';
recommends 'JSON::XS', '2.0';
on 'test' => sub {
    requires 'Test::More', '0.98';
};
`
	if err := os.WriteFile(filepath.Join(dir, "cpanfile"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]PerlPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["LWP::UserAgent"]; !ok {
		t.Error("expected 'LWP::UserAgent' in packages")
	}
	if byName["LWP::UserAgent"].Version != "6.0" {
		t.Errorf("LWP::UserAgent version: got %q, want %q", byName["LWP::UserAgent"].Version, "6.0")
	}
	if _, ok := byName["Moose"]; !ok {
		t.Error("expected 'Moose' in packages")
	}
	for _, p := range pkgs {
		if !p.Direct {
			t.Errorf("package %q should be Direct=true in cpanfile fallback", p.Name)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Perl lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	// Note: "use " is a call-site pattern that maps to [plugin], so any file
	// with "use Module" will produce at least a plugin capability.
	src := `#!/usr/bin/perl
use LWP::UserAgent;

my $ua = LWP::UserAgent->new;

sub run_cmd {
    my $cmd = shift;
    system($cmd);
}

my $secret = $ENV{"SECRET_KEY"};
`
	if err := os.WriteFile(filepath.Join(dir, "script.pl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "exec", "env", "plugin"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

// TestDetectNoCapabilities verifies that a Perl file with no imports or
// sensitive call-sites produces no capabilities. Note: "use " is a call-site
// pattern, so we intentionally omit use statements here.
func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `#!/usr/bin/perl

sub add {
    my ($a, $b) = @_;
    return $a + $b;
}

sub greet {
    my $name = shift;
    return "Hello, $name";
}
`
	if err := os.WriteFile(filepath.Join(dir, "utils.pl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter integration tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := Adapter{}
	if a.Name() != "perl" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "perl")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()
	content := `requires 'LWP::UserAgent', '6.0';
requires 'Moose';
`
	if err := os.WriteFile(filepath.Join(dir, "cpanfile"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	a := Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules, got %d", len(g.Modules))
	}
	if _, ok := g.Packages["LWP::UserAgent"]; !ok {
		t.Error("expected 'LWP::UserAgent' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseCpanfileSnapshot(f *testing.F) {
	f.Add([]byte("# carton snapshot format: version 1.0\nDISTRIBUTIONS\n  Carp-1.50\n    provides:\n      Carp 1.50\n"))
	f.Add([]byte(""))
	f.Add([]byte("DISTRIBUTIONS\n"))
	f.Add([]byte("not a snapshot"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cpanfile.snapshot"), data, 0o600); err != nil {
			return
		}
		loadCpanfileSnapshot(dir) //nolint:errcheck
	})
}
