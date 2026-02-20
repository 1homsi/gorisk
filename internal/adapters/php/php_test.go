package php

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

// ── lockfile ──────────────────────────────────────────────────────────────────

func TestLoadComposerLock(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "packages": [
    {
      "name": "guzzlehttp/guzzle",
      "version": "7.5.0",
      "require": {
        "guzzlehttp/psr7": "^2.0",
        "php": "^7.2"
      }
    },
    {
      "name": "symfony/process",
      "version": "6.0.0",
      "require": {}
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "10.0.0",
      "require": {}
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}

	// Mark guzzle as direct dep
	composerJSON := `{"require":{"guzzlehttp/guzzle":"^7.0"},"require-dev":{"phpunit/phpunit":"^10.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(composerJSON), 0600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(pkgs) != 3 {
		t.Errorf("expected 3 packages, got %d", len(pkgs))
	}

	// Check guzzle is present and direct
	var guzzle *ComposerPackage
	for i := range pkgs {
		if pkgs[i].Name == "guzzlehttp/guzzle" {
			guzzle = &pkgs[i]
		}
	}
	if guzzle == nil {
		t.Fatal("expected guzzlehttp/guzzle in packages")
	}
	if guzzle.Version != "7.5.0" {
		t.Errorf("guzzle version = %q, want 7.5.0", guzzle.Version)
	}
	if !guzzle.Direct {
		t.Error("guzzle should be a direct dependency")
	}
	// php and ext-* deps should be filtered out
	for _, dep := range guzzle.Dependencies {
		if dep == "php" {
			t.Error("php should be filtered from dependencies")
		}
	}
}

func TestLoadNoLockfile(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error when composer.lock is absent")
	}
}

func TestReadDirectDeps(t *testing.T) {
	dir := t.TempDir()
	composerJSON := `{
    "require": {"foo/bar": "^1.0"},
    "require-dev": {"baz/qux": "^2.0"}
  }`
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(composerJSON), 0600); err != nil {
		t.Fatal(err)
	}

	deps := readDirectDeps(dir)
	if !deps["foo/bar"] {
		t.Error("expected foo/bar in direct deps")
	}
	if !deps["baz/qux"] {
		t.Error("expected baz/qux in direct deps")
	}
}

func TestReadDirectDepsNoFile(t *testing.T) {
	dir := t.TempDir()
	deps := readDirectDeps(dir)
	if len(deps) != 0 {
		t.Errorf("expected empty deps for missing composer.json, got %v", deps)
	}
}

// ── capability detection ──────────────────────────────────────────────────────

func TestDetectCallSites(t *testing.T) {
	dir := t.TempDir()
	phpCode := `<?php
$output = shell_exec('ls -la');
$env = getenv('HOME');
$data = file_get_contents('config.json');
file_put_contents('/tmp/out.txt', $data);
`
	if err := os.WriteFile(filepath.Join(dir, "test.php"), []byte(phpCode), 0600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	for _, expected := range []capability.Capability{
		capability.CapExec,
		capability.CapEnv,
		capability.CapFSRead,
		capability.CapFSWrite,
	} {
		if !caps.Has(expected) {
			t.Errorf("expected capability %q from PHP call sites", expected)
		}
	}
}

func TestDetectUseStatement(t *testing.T) {
	dir := t.TempDir()
	phpCode := `<?php
use GuzzleHttp\Client;
use SymfonyProcess\Process;

$client = new Client();
`
	if err := os.WriteFile(filepath.Join(dir, "main.php"), []byte(phpCode), 0600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has(capability.CapNetwork) {
		t.Error("expected network capability from GuzzleHttp use statement")
	}
}

func TestDetectEmptyDir(t *testing.T) {
	dir := t.TempDir()
	caps := Detect(dir)
	if caps.Score != 0 {
		t.Errorf("expected zero score for empty dir, got %d", caps.Score)
	}
}

func TestDetectNonPHPFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	// Put dangerous call in a JS file — should not be detected
	if err := os.WriteFile(filepath.Join(dir, "script.js"), []byte("exec('ls')"), 0600); err != nil {
		t.Fatal(err)
	}
	caps := Detect(dir)
	if caps.Score != 0 {
		t.Errorf("expected zero score (non-.php file), got %d", caps.Score)
	}
}

func TestScanFileCryptoAndReflect(t *testing.T) {
	dir := t.TempDir()
	phpCode := `<?php
$hash = password_hash($password, PASSWORD_BCRYPT);
$r = new ReflectionClass($obj);
$enc = openssl_encrypt($data, 'AES-256-CBC', $key);
`
	if err := os.WriteFile(filepath.Join(dir, "crypto.php"), []byte(phpCode), 0600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has(capability.CapCrypto) {
		t.Error("expected crypto capability")
	}
	if !caps.Has(capability.CapReflect) {
		t.Error("expected reflect capability")
	}
}

func TestScanFileUnsafe(t *testing.T) {
	dir := t.TempDir()
	phpCode := `<?php
$result = eval($userInput);
`
	if err := os.WriteFile(filepath.Join(dir, "unsafe.php"), []byte(phpCode), 0600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has(capability.CapUnsafe) {
		t.Error("expected unsafe capability from eval()")
	}
}

func TestScanFileEnvVars(t *testing.T) {
	dir := t.TempDir()
	phpCode := `<?php
$key = $_SERVER['API_KEY'];
$region = $_ENV['AWS_REGION'];
`
	if err := os.WriteFile(filepath.Join(dir, "env.php"), []byte(phpCode), 0600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has(capability.CapEnv) {
		t.Error("expected env capability from $_SERVER and $_ENV")
	}
}

// ── adapter / Load ────────────────────────────────────────────────────────────

func TestAdapterName(t *testing.T) {
	a := &Adapter{}
	if a.Name() != "php" {
		t.Errorf("Name() = %q, want php", a.Name())
	}
}

func TestAdapterLoadBasic(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "packages": [
    {"name": "aws/aws-sdk-php", "version": "3.130.2", "require": {}}
  ],
  "packages-dev": []
}`
	composerJSON := `{"name": "myapp/api", "require": {"aws/aws-sdk-php": "^3.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(composerJSON), 0600); err != nil {
		t.Fatal(err)
	}

	a := &Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if g.Main == nil {
		t.Fatal("expected non-nil Main module")
	}
	if g.Main.Path != "myapp/api" {
		t.Errorf("Main.Path = %q, want myapp/api", g.Main.Path)
	}
	if _, ok := g.Modules["aws/aws-sdk-php"]; !ok {
		t.Error("expected aws/aws-sdk-php in modules")
	}
	// aws/aws-sdk-php is a known package — should get import capabilities
	pkg := g.Packages["aws/aws-sdk-php"]
	if pkg == nil {
		t.Fatal("expected aws/aws-sdk-php package")
	}
	if !pkg.Capabilities.Has(capability.CapNetwork) {
		t.Error("expected network capability for aws/aws-sdk-php")
	}
}

func TestAdapterLoadNoLockfile(t *testing.T) {
	dir := t.TempDir()
	a := &Adapter{}
	_, err := a.Load(dir)
	if err == nil {
		t.Error("expected error when no composer.lock")
	}
}

func TestAdapterLoadWithPHPSource(t *testing.T) {
	dir := t.TempDir()
	lock := `{"packages": [], "packages-dev": []}`
	composerJSON := `{"name": "myapp/backend"}`
	phpCode := `<?php
exec('backup.sh');
$data = file_get_contents('data.json');
`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(composerJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte(phpCode), 0600); err != nil {
		t.Fatal(err)
	}

	a := &Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Root package should have capabilities from PHP source scan
	root := g.Packages["myapp/backend"]
	if root == nil {
		t.Fatal("expected root package")
	}
	if !root.Capabilities.Has(capability.CapExec) {
		t.Error("expected exec capability from root PHP source")
	}
}

func TestReadComposerJSONName(t *testing.T) {
	dir := t.TempDir()

	// No composer.json → empty string
	if name := readComposerJSONName(dir); name != "" {
		t.Errorf("expected empty name for missing file, got %q", name)
	}

	// With composer.json
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"name":"vendor/project"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if name := readComposerJSONName(dir); name != "vendor/project" {
		t.Errorf("readComposerJSONName = %q, want vendor/project", name)
	}
}
