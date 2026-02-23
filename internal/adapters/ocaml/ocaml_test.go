package ocaml

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadOpamLocked(t *testing.T) {
	dir := t.TempDir()

	lockedContent := `opam-version: "2.0"
depends: [
  "astring" {= "0.8.5"}
  "base" {= "v0.16.3"}
  "cohttp" {= "5.3.1"}
  "cohttp-lwt-unix" {= "5.3.1"}
  "ocaml" {= "5.1.1" & preinstalled}
]
`
	// Source .opam marks cohttp and base as direct.
	srcContent := `opam-version: "2.0"
depends: [
  "cohttp" {>= "5.0"}
  "base" {>= "v0.14"}
]
`
	if err := os.WriteFile(filepath.Join(dir, "myproject.opam.locked"), []byte(lockedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "myproject.opam"), []byte(srcContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]OCamlPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["cohttp"]; !ok {
		t.Error("expected 'cohttp' in packages")
	}
	if byName["cohttp"].Version != "5.3.1" {
		t.Errorf("cohttp version: got %q, want %q", byName["cohttp"].Version, "5.3.1")
	}
	if !byName["cohttp"].Direct {
		t.Error("cohttp should be a direct dep (listed in .opam)")
	}
	if _, ok := byName["base"]; !ok {
		t.Error("expected 'base' in packages")
	}
	if !byName["base"].Direct {
		t.Error("base should be a direct dep (listed in .opam)")
	}
	// astring is in locked but not in source .opam — transitive.
	if byName["astring"].Direct {
		t.Error("astring should not be a direct dep")
	}
	if byName["astring"].Version != "0.8.5" {
		t.Errorf("astring version: got %q, want %q", byName["astring"].Version, "0.8.5")
	}
}

func TestLoadOpam(t *testing.T) {
	dir := t.TempDir()

	content := `opam-version: "2.0"
name: "myproject"
depends: [
  "cohttp" {>= "5.0"}
  "lwt" {>= "5.0"}
  "yojson" {>= "2.0"}
]
`
	if err := os.WriteFile(filepath.Join(dir, "myproject.opam"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]OCamlPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"cohttp", "lwt", "yojson"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
		if !byName[want].Direct {
			t.Errorf("%q should be Direct=true in .opam fallback", want)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no OCaml lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `open Cohttp
open Unix

let () =
  let _ = Unix.system "ls" in
  let _ = open_in "/etc/passwd" in
  ()
`
	if err := os.WriteFile(filepath.Join(dir, "main.ml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	// "open Cohttp" → network; "open Unix" → exec/network/...; "Unix.system " → exec; "open_in " → fs:read
	wantCaps := []string{"network", "exec", "fs:read"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected, got: %v", want, caps.List())
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `let add a b = a + b

let greet name = Printf.sprintf "Hello, %s!" name
`
	if err := os.WriteFile(filepath.Join(dir, "utils.ml"), []byte(src), 0o600); err != nil {
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
	if a.Name() != "ocaml" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "ocaml")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	lockedContent := `opam-version: "2.0"
depends: [
  "cohttp" {= "5.3.1"}
  "lwt" {= "5.7.0"}
]
`
	srcContent := `opam-version: "2.0"
depends: [
  "cohttp" {>= "5.0"}
  "lwt" {>= "5.0"}
]
`
	if err := os.WriteFile(filepath.Join(dir, "myproject.opam.locked"), []byte(lockedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "myproject.opam"), []byte(srcContent), 0o600); err != nil {
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
	if _, ok := g.Packages["cohttp"]; !ok {
		t.Error("expected 'cohttp' package in graph")
	}
	if _, ok := g.Packages["lwt"]; !ok {
		t.Error("expected 'lwt' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseOpamLocked(f *testing.F) {
	f.Add([]byte(`opam-version: "2.0"
depends: [
  "cohttp" {= "5.3.1"}
]
`))
	f.Add([]byte(""))
	f.Add([]byte("# comment only\n"))
	f.Add([]byte(`depends: [`))
	f.Add([]byte(`depends: [
]
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "myproject.opam.locked"), data, 0o600); err != nil {
			return
		}
		Load(dir) //nolint:errcheck
	})
}
