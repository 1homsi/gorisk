package erlang

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadRebarLock(t *testing.T) {
	dir := t.TempDir()

	content := `{"1.2.0",
[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>,<<"sha256:abc">>,<<"sha256:def">>},0},
 {<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>,<<"sha256:abc">>,<<"sha256:def">>},1},
 {<<"hackney">>,{pkg,<<"hackney">>,<<"1.20.1">>,<<"sha256:abc">>,<<"sha256:def">>},1}
]}.
`
	if err := os.WriteFile(filepath.Join(dir, "rebar.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(rebar.lock): %v", err)
	}

	byName := make(map[string]ErlangPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["cowboy"]; !ok {
		t.Error("expected 'cowboy' in packages")
	}
	if byName["cowboy"].Version != "2.10.0" {
		t.Errorf("cowboy version: got %q, want %q", byName["cowboy"].Version, "2.10.0")
	}
	if !byName["cowboy"].Direct {
		t.Error("cowboy (depth 0) should be a direct dep")
	}
	if byName["cowlib"].Direct {
		t.Error("cowlib (depth 1) should be a transitive dep")
	}
	if byName["hackney"].Direct {
		t.Error("hackney (depth 1) should be a transitive dep")
	}
	if byName["hackney"].Version != "1.20.1" {
		t.Errorf("hackney version: got %q, want %q", byName["hackney"].Version, "1.20.1")
	}
}

func TestLoadRebarConfig(t *testing.T) {
	dir := t.TempDir()

	content := `{erl_opts, [debug_info]}.
{deps, [
    {cowboy, "2.10.0"},
    {hackney, {git, "https://github.com/benoitc/hackney.git", {tag, "1.20.1"}}},
    {jsx, "3.1.0"}
]}.
`
	if err := os.WriteFile(filepath.Join(dir, "rebar.config"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(rebar.config): %v", err)
	}

	byName := make(map[string]ErlangPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["cowboy"]; !ok {
		t.Error("expected 'cowboy' in packages")
	}
	if byName["cowboy"].Version != "2.10.0" {
		t.Errorf("cowboy version: got %q, want %q", byName["cowboy"].Version, "2.10.0")
	}
	if !byName["cowboy"].Direct {
		t.Error("cowboy should be a direct dep")
	}
	if _, ok := byName["hackney"]; !ok {
		t.Error("expected 'hackney' (git dep) in packages")
	}
	if !byName["hackney"].Direct {
		t.Error("hackney should be a direct dep")
	}
	if _, ok := byName["jsx"]; !ok {
		t.Error("expected 'jsx' in packages")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Erlang dependency files")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `-module(myapp).
-export([run/1, read/1]).

run(Cmd) ->
    os:cmd(Cmd).

read(Path) ->
    file:read_file(Path).
`
	if err := os.WriteFile(filepath.Join(dir, "myapp.erl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"exec", "fs:read"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `-module(math_utils).
-export([add/2, greet/1]).

add(A, B) -> A + B.

greet(Name) -> "Hello, " ++ Name.
`
	if err := os.WriteFile(filepath.Join(dir, "math_utils.erl"), []byte(src), 0o600); err != nil {
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
	if a.Name() != "erlang" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "erlang")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	content := `{"1.2.0",
[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>,<<"sha256:abc">>,<<"sha256:def">>},0},
 {<<"hackney">>,{pkg,<<"hackney">>,<<"1.20.1">>,<<"sha256:abc">>,<<"sha256:def">>},1}
]}.
`
	if err := os.WriteFile(filepath.Join(dir, "rebar.lock"), []byte(content), 0o600); err != nil {
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

	if _, ok := g.Packages["cowboy"]; !ok {
		t.Error("expected 'cowboy' package in graph")
	}
	if _, ok := g.Packages["hackney"]; !ok {
		t.Error("expected 'hackney' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseRebarLock(f *testing.F) {
	f.Add([]byte(`{"1.2.0",
[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>,<<"sha256:abc">>,<<"sha256:def">>},0}
]}.`))
	f.Add([]byte(``))
	f.Add([]byte(`% comment only`))
	f.Add([]byte(`{"1.0.0",[]}.`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "rebar.lock"), data, 0o600); err != nil {
			return
		}
		loadRebarLock(dir) //nolint:errcheck
	})
}
