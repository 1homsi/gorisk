package haskell

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadCabalFreeze(t *testing.T) {
	dir := t.TempDir()
	content := `constraints: any.aeson ==2.2.1.0,
             any.attoparsec ==0.14.4,
             any.base ==4.18.2.1,
             any.http-conduit ==2.3.8,
             any.process ==1.6.18.0
`
	if err := os.WriteFile(filepath.Join(dir, "cabal.project.freeze"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]HaskellPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"aeson", "attoparsec", "base", "http-conduit", "process"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
	}
	if byName["aeson"].Version != "2.2.1.0" {
		t.Errorf("aeson version: got %q, want %q", byName["aeson"].Version, "2.2.1.0")
	}
}

func TestLoadStackLock(t *testing.T) {
	dir := t.TempDir()
	content := `packages:
- completed:
    hackage: aeson-2.2.1.0@sha256:abc123,size:12345
    pantry-tree:
      sha256: def456
      size: 123
  original:
    hackage: aeson-2.2.1.0
- completed:
    hackage: http-conduit-2.3.8@sha256:xyz789,size:5678
  original:
    hackage: http-conduit-2.3.8
- completed:
    hackage: process-1.6.18.0
`
	if err := os.WriteFile(filepath.Join(dir, "stack.yaml.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]HaskellPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"aeson", "http-conduit", "process"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
	}
	if byName["aeson"].Version != "2.2.1.0" {
		t.Errorf("aeson version: got %q, want %q", byName["aeson"].Version, "2.2.1.0")
	}
}

func TestLoadCabalFile(t *testing.T) {
	dir := t.TempDir()
	content := `name:          myproject
version:       0.1.0.0
build-type:    Simple

executable myproject
  hs-source-dirs: src
  main-is:        Main.hs
  build-depends:
      base >=4.14 && <5,
      aeson ^>=2.1,
      http-conduit >= 2.3,
      process
  default-language: Haskell2010
`
	if err := os.WriteFile(filepath.Join(dir, "myproject.cabal"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]HaskellPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range []string{"base", "aeson", "http-conduit", "process"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected %q in packages", want)
		}
	}
	if !byName["aeson"].Direct {
		t.Error("aeson should be direct")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Haskell lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `module Main where

import System.Process (createProcess, proc)
import System.Environment (getEnv)

main :: IO ()
main = do
  env <- System.Environment.getEnv "HOME"
  _ <- System.Process.createProcess (proc "ls" ["-la"])
  putStrLn env
`
	if err := os.WriteFile(filepath.Join(dir, "Main.hs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	for _, want := range []string{"exec", "env"} {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected, got: %v", want, caps.List())
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `module Utils where

add :: Int -> Int -> Int
add a b = a + b

greet :: String -> String
greet name = "Hello, " ++ name
`
	if err := os.WriteFile(filepath.Join(dir, "Utils.hs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

func TestDetectUnsafe(t *testing.T) {
	dir := t.TempDir()
	src := `module Unsafe where

import System.IO.Unsafe (unsafePerformIO)

dangerousValue :: Int
dangerousValue = unsafePerformIO (return 42)
`
	if err := os.WriteFile(filepath.Join(dir, "Unsafe.hs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has("unsafe") {
		t.Errorf("expected 'unsafe' capability, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := Adapter{}
	if a.Name() != "haskell" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "haskell")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()
	content := `constraints: any.aeson ==2.2.1.0,
             any.http-conduit ==2.3.8
`
	if err := os.WriteFile(filepath.Join(dir, "cabal.project.freeze"), []byte(content), 0o600); err != nil {
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
	if _, ok := g.Packages["aeson"]; !ok {
		t.Error("expected 'aeson' package in graph")
	}
	if _, ok := g.Packages["http-conduit"]; !ok {
		t.Error("expected 'http-conduit' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseCabalFreeze(f *testing.F) {
	f.Add([]byte("constraints: any.aeson ==2.2.1.0,\n             any.base ==4.18.2.1\n"))
	f.Add([]byte(""))
	f.Add([]byte("-- comment only\n"))
	f.Add([]byte("constraints:\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cabal.project.freeze"), data, 0o600); err != nil {
			return
		}
		loadCabalFreeze(dir) //nolint:errcheck
	})
}
