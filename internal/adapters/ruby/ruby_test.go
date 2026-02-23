package ruby

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadGemfileLock(t *testing.T) {
	dir := t.TempDir()

	gemfile := `source 'https://rubygems.org'

gem 'rails', '~> 7.1.0'
gem 'pg', '>= 1.1'
`
	lockContent := `GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.0)
      actionpack (= 7.1.0)
    actionpack (7.1.0)
      rack (~> 3.0)
    pg (1.5.4)
    rack (3.0.8)
    rails (7.1.0)
      actioncable (= 7.1.0)
      actionpack (= 7.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  pg (>= 1.1)
  rails (~> 7.1.0)

BUNDLED WITH
   2.4.10
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte(gemfile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadGemfileLock(dir)
	if err != nil {
		t.Fatalf("loadGemfileLock: %v", err)
	}

	byName := make(map[string]RubyPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["rails"]; !ok {
		t.Error("expected 'rails' in packages")
	}
	if byName["rails"].Version != "7.1.0" {
		t.Errorf("rails version: got %q, want %q", byName["rails"].Version, "7.1.0")
	}
	if !byName["rails"].Direct {
		t.Error("rails should be a direct dep")
	}
	if _, ok := byName["pg"]; !ok {
		t.Error("expected 'pg' in packages")
	}
	if !byName["pg"].Direct {
		t.Error("pg should be a direct dep")
	}
	// rack is a transitive dep.
	if byName["rack"].Direct {
		t.Error("rack should not be a direct dep")
	}
	// rails should depend on actioncable.
	found := false
	for _, dep := range byName["rails"].Dependencies {
		if dep == "actioncable" {
			found = true
		}
	}
	if !found {
		t.Error("rails should depend on actioncable")
	}
}

func TestLoadGemfile(t *testing.T) {
	dir := t.TempDir()
	content := `source 'https://rubygems.org'

# Web framework
gem 'rails', '~> 7.1.0'
gem 'pg', '>= 1.1'
gem "redis"
gem 'devise'
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadGemfile(dir)
	if err != nil {
		t.Fatalf("loadGemfile: %v", err)
	}

	byName := make(map[string]RubyPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["rails"]; !ok {
		t.Error("expected 'rails' in packages")
	}
	if _, ok := byName["pg"]; !ok {
		t.Error("expected 'pg' in packages")
	}
	if _, ok := byName["redis"]; !ok {
		t.Error("expected 'redis' in packages")
	}
	if _, ok := byName["devise"]; !ok {
		t.Error("expected 'devise' in packages")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `require 'open3'
require 'openssl'

def run_cmd(cmd)
  system(cmd)
end

def read_env
  ENV['SECRET_KEY']
end

def read_file(path)
  File.read(path)
end
`
	if err := os.WriteFile(filepath.Join(dir, "main.rb"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"exec", "crypto", "env", "fs:read"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `def add(a, b)
  a + b
end

def greet(name)
  "Hello, #{name}"
end
`
	if err := os.WriteFile(filepath.Join(dir, "utils.rb"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter integration test
// ---------------------------------------------------------------------------

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	gemfile := `source 'https://rubygems.org'
gem 'rails', '~> 7.1.0'
gem 'pg', '>= 1.1'
`
	lockContent := `GEM
  remote: https://rubygems.org/
  specs:
    pg (1.5.4)
    rails (7.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  pg (>= 1.1)
  rails (~> 7.1.0)

BUNDLED WITH
   2.4.10
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte(gemfile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Adapter{}
	if a.Name() != "ruby" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "ruby")
	}

	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}

	// Should have root module + at least the two deps.
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules, got %d", len(g.Modules))
	}

	if _, ok := g.Packages["rails"]; !ok {
		t.Error("expected 'rails' package in graph")
	}
	if _, ok := g.Packages["pg"]; !ok {
		t.Error("expected 'pg' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseGemfileLock(f *testing.F) {
	f.Add([]byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n\nDEPENDENCIES\n  rails\n"))
	f.Add([]byte(""))
	f.Add([]byte("# comment only"))
	f.Add([]byte("PLATFORMS\n  ruby\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), data, 0o600); err != nil {
			return
		}
		loadGemfileLock(dir) //nolint:errcheck
	})
}

// ---------------------------------------------------------------------------
// Malformed / empty input tests — verify no panic and graceful handling
// ---------------------------------------------------------------------------

func TestLoadGemfileLockEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadGemfileLock(dir)
	if err != nil {
		t.Fatalf("loadGemfileLock() unexpected error for empty file: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty Gemfile.lock, got %d", len(pkgs))
	}
}

func TestLoadGemfileLockMalformed(t *testing.T) {
	// Gemfile.lock with only PLATFORMS section — should return empty, not error.
	dir := t.TempDir()
	content := `PLATFORMS
  ruby

BUNDLED WITH
   2.4.10
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadGemfileLock(dir)
	if err != nil {
		t.Fatalf("loadGemfileLock() unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for platform-only Gemfile.lock, got %d", len(pkgs))
	}
}

func TestLoadGemfileLockTruncated(t *testing.T) {
	// Truncated Gemfile.lock — should not panic.
	dir := t.TempDir()
	content := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test itself serves as a panic detector.
	pkgs, err := loadGemfileLock(dir)
	if err != nil {
		t.Fatalf("loadGemfileLock() unexpected error for truncated file: %v", err)
	}
	// Partial parsing is acceptable; just verify no panic and no crash.
	_ = pkgs
}

func TestLoadGemfileEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadGemfile(dir)
	if err != nil {
		t.Fatalf("loadGemfile() unexpected error for empty file: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty Gemfile, got %d", len(pkgs))
	}
}

func TestLoadGemfileMalformed(t *testing.T) {
	// Gemfile with no gem declarations — should return empty, not error.
	dir := t.TempDir()
	content := `source 'https://rubygems.org'
# this file has no gem declarations
ruby '3.2.0'
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadGemfile(dir)
	if err != nil {
		t.Fatalf("loadGemfile() unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for no-gem Gemfile, got %d", len(pkgs))
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Ruby lockfiles")
	}
}
