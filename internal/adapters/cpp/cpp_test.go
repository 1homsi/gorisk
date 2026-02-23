package cpp

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadVcpkgJSON(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "my-project",
  "version": "1.0.0",
  "dependencies": [
    "curl",
    "openssl",
    { "name": "sqlite3", "version>=": "3.43.0" },
    { "name": "boost-asio", "features": ["ssl"] }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "vcpkg.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]CppPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"curl", "openssl", "sqlite3", "boost-asio"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
	}
	if byName["sqlite3"].Version != "3.43.0" {
		t.Errorf("sqlite3 version: got %q, want %q", byName["sqlite3"].Version, "3.43.0")
	}
	if !byName["curl"].Direct {
		t.Error("curl should be direct")
	}
}

func TestLoadConanfilePy(t *testing.T) {
	dir := t.TempDir()
	content := `from conans import ConanFile

class MyProject(ConanFile):
    name = "myproject"
    version = "1.0"

    def requirements(self):
        self.requires("curl/7.86.0")
        self.requires("openssl/3.1.4@conan/stable")
        self.requires("sqlite3/3.43.2")
`
	if err := os.WriteFile(filepath.Join(dir, "conanfile.py"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]CppPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"curl", "openssl", "sqlite3"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
	}
	if byName["curl"].Version != "7.86.0" {
		t.Errorf("curl version: got %q, want %q", byName["curl"].Version, "7.86.0")
	}
}

func TestLoadConanfileTxt(t *testing.T) {
	dir := t.TempDir()
	content := `[requires]
curl/7.86.0
openssl/3.1.4
sqlite3/3.43.2

[options]
curl:shared=True

[generators]
cmake
`
	if err := os.WriteFile(filepath.Join(dir, "conanfile.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]CppPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"curl", "openssl", "sqlite3"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
	}
	if byName["openssl"].Version != "3.1.4" {
		t.Errorf("openssl version: got %q, want %q", byName["openssl"].Version, "3.1.4")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no C/C++ manifest")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `#include <stdio.h>
#include <stdlib.h>

int main() {
    system("ls -la");
    FILE *f = fopen("/etc/passwd", "r");
    if (f) fclose(f);
    return 0;
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	for _, want := range []string{"exec", "fs:read", "fs:write"} {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `#include <stdint.h>

int add(int a, int b) {
    return a + b;
}

const char* greet(const char* name) {
    return name;
}
`
	if err := os.WriteFile(filepath.Join(dir, "utils.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

func TestDetectIncludeCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `#include <curl/curl.h>
#include <openssl/ssl.h>

void fetch(const char* url) {
    CURL *curl = curl_easy_init();
    curl_easy_cleanup(curl);
}
`
	if err := os.WriteFile(filepath.Join(dir, "http.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	for _, want := range []string{"network", "crypto"} {
		if !caps.Has(want) {
			t.Errorf("expected capability %q from #include, got caps: %v", want, caps.List())
		}
	}
}

// ---------------------------------------------------------------------------
// Adapter tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := Adapter{}
	if a.Name() != "cpp" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "cpp")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "my-project",
  "dependencies": ["curl", "openssl"]
}`
	if err := os.WriteFile(filepath.Join(dir, "vcpkg.json"), []byte(content), 0o600); err != nil {
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
	if _, ok := g.Packages["curl"]; !ok {
		t.Error("expected 'curl' package in graph")
	}
	if _, ok := g.Packages["openssl"]; !ok {
		t.Error("expected 'openssl' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseVcpkgJSON(f *testing.F) {
	f.Add([]byte(`{"dependencies":["curl","openssl"]}`))
	f.Add([]byte(`{"dependencies":[{"name":"sqlite3","version>=":"3.43.0"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "vcpkg.json"), data, 0o600); err != nil {
			return
		}
		loadVcpkgJSON(dir) //nolint:errcheck
	})
}
