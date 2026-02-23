package julia

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadManifestToml(t *testing.T) {
	dir := t.TempDir()

	manifestContent := `# This file is machine-generated - editing it directly is not advised

julia_version = "1.10.0"
manifest_format = "2.0"
project_hash = "abc123"

[[deps.CSV]]
deps = ["CodecZlib", "Dates"]
git-tree-sha1 = "abc123"
uuid = "336ed68f-0bac-5ca0-87d4-7b16caf5d03b"
version = "0.10.12"

[[deps.HTTP]]
deps = ["Base64", "CodecZlib"]
git-tree-sha1 = "def456"
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "1.10.1"

[[deps.CodecZlib]]
uuid = "944b1d66-785c-5afd-91f1-9de20f533193"
version = "0.7.3"
`
	projectContent := `name = "MyProject"
uuid = "abc123"
version = "0.1.0"

[deps]
CSV = "336ed68f-0bac-5ca0-87d4-7b16caf5d03b"
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
`
	if err := os.WriteFile(filepath.Join(dir, "Manifest.toml"), []byte(manifestContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Project.toml"), []byte(projectContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]JuliaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["CSV"]; !ok {
		t.Error("expected 'CSV' in packages")
	}
	if byName["CSV"].Version != "0.10.12" {
		t.Errorf("CSV version: got %q, want %q", byName["CSV"].Version, "0.10.12")
	}
	if byName["CSV"].UUID != "336ed68f-0bac-5ca0-87d4-7b16caf5d03b" {
		t.Errorf("CSV uuid: got %q", byName["CSV"].UUID)
	}
	if !byName["CSV"].Direct {
		t.Error("CSV should be direct (listed in Project.toml [deps])")
	}
	if !byName["HTTP"].Direct {
		t.Error("HTTP should be direct (listed in Project.toml [deps])")
	}
	// CodecZlib is transitive — not in Project.toml.
	if byName["CodecZlib"].Direct {
		t.Error("CodecZlib should not be a direct dep")
	}
}

func TestLoadProjectToml(t *testing.T) {
	dir := t.TempDir()

	content := `name = "MyProject"
uuid = "abc123"
authors = ["Alice"]
version = "0.1.0"

[deps]
CSV = "336ed68f-0bac-5ca0-87d4-7b16caf5d03b"
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
Plots = "91a5bcdd-55d7-5caf-9e0b-520d859cae80"
`
	if err := os.WriteFile(filepath.Join(dir, "Project.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]JuliaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"CSV", "HTTP", "Plots"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
		if !byName[want].Direct {
			t.Errorf("%q should be Direct=true in Project.toml fallback", want)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Julia lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `using HTTP
import CSV

function fetch_data(url)
    resp = HTTP.get(url)
    run(` + "`ls -la`" + `)
    return resp.body
end
`
	if err := os.WriteFile(filepath.Join(dir, "main.jl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "exec"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected, got: %v", want, caps.List())
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `function add(a, b)
    return a + b
end

function greet(name)
    return "Hello, $name!"
end
`
	if err := os.WriteFile(filepath.Join(dir, "utils.jl"), []byte(src), 0o600); err != nil {
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
	if a.Name() != "julia" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "julia")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	manifestContent := `julia_version = "1.10.0"
manifest_format = "2.0"

[[deps.HTTP]]
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "1.10.1"

[[deps.CSV]]
uuid = "336ed68f-0bac-5ca0-87d4-7b16caf5d03b"
version = "0.10.12"
`
	projectContent := `[deps]
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
CSV = "336ed68f-0bac-5ca0-87d4-7b16caf5d03b"
`
	if err := os.WriteFile(filepath.Join(dir, "Manifest.toml"), []byte(manifestContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Project.toml"), []byte(projectContent), 0o600); err != nil {
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
	if g.Main == nil {
		t.Error("expected non-nil Main module")
	}
	if _, ok := g.Packages["HTTP"]; !ok {
		t.Error("expected 'HTTP' package in graph")
	}
	if _, ok := g.Packages["CSV"]; !ok {
		t.Error("expected 'CSV' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseManifestToml(f *testing.F) {
	f.Add([]byte(`julia_version = "1.10.0"
manifest_format = "2.0"

[[deps.HTTP]]
uuid = "cd3eb016"
version = "1.10.1"
`))
	f.Add([]byte(""))
	f.Add([]byte("# comment only\n"))
	f.Add([]byte(`[[deps.`))
	f.Add([]byte(`[[deps.CSV]]
version = "0.10.12"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Manifest.toml"), data, 0o600); err != nil {
			return
		}
		Load(dir) //nolint:errcheck
	})
}
