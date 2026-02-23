package clojure

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadDepsEdn(t *testing.T) {
	dir := t.TempDir()

	content := `{:deps {org.clojure/clojure {:mvn/version "1.11.1"}
         clj-http/clj-http {:mvn/version "3.12.3"}
         ring/ring-core {:mvn/version "1.11.0"}}
 :aliases {:dev {:extra-deps {criterium/criterium {:mvn/version "0.4.6"}}}}}
`
	if err := os.WriteFile(filepath.Join(dir, "deps.edn"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(deps.edn): %v", err)
	}

	byName := make(map[string]ClojurePackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["org.clojure/clojure"]; !ok {
		t.Error("expected 'org.clojure/clojure' in packages")
	}
	if byName["org.clojure/clojure"].Version != "1.11.1" {
		t.Errorf("org.clojure/clojure version: got %q, want %q",
			byName["org.clojure/clojure"].Version, "1.11.1")
	}
	if !byName["org.clojure/clojure"].Direct {
		t.Error("org.clojure/clojure should be a direct dep")
	}
	if _, ok := byName["clj-http/clj-http"]; !ok {
		t.Error("expected 'clj-http/clj-http' in packages")
	}
	if !byName["clj-http/clj-http"].Direct {
		t.Error("clj-http/clj-http should be a direct dep")
	}
	// criterium is under :aliases — should be indirect.
	if crit, ok := byName["criterium/criterium"]; ok {
		if crit.Direct {
			t.Error("criterium/criterium should be an indirect (alias) dep")
		}
	}
}

func TestLoadProjectClj(t *testing.T) {
	dir := t.TempDir()

	content := `(defproject myapp "0.1.0-SNAPSHOT"
  :description "A sample project"
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [ring/ring-core "1.11.0"]
                 [compojure "1.7.1"]]
  :main myapp.core)
`
	if err := os.WriteFile(filepath.Join(dir, "project.clj"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(project.clj): %v", err)
	}

	byName := make(map[string]ClojurePackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["org.clojure/clojure"]; !ok {
		t.Error("expected 'org.clojure/clojure' in packages")
	}
	if byName["org.clojure/clojure"].Version != "1.11.1" {
		t.Errorf("org.clojure/clojure version: got %q, want %q",
			byName["org.clojure/clojure"].Version, "1.11.1")
	}
	if !byName["org.clojure/clojure"].Direct {
		t.Error("org.clojure/clojure should be a direct dep")
	}
	if _, ok := byName["ring/ring-core"]; !ok {
		t.Error("expected 'ring/ring-core' in packages")
	}
	if _, ok := byName["compojure"]; !ok {
		t.Error("expected 'compojure' in packages")
	}
	if byName["compojure"].Version != "1.7.1" {
		t.Errorf("compojure version: got %q, want %q", byName["compojure"].Version, "1.7.1")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Clojure dependency files")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `(ns myapp.core
  (:require [clj-http.client :as http]
            [clojure.java.io :as io]))

(defn fetch-data [url]
  (http/get url))

(defn read-config [path]
  (slurp path))
`
	if err := os.WriteFile(filepath.Join(dir, "core.clj"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "fs:read"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `(ns myapp.utils)

(defn add [a b]
  (+ a b))

(defn greet [name]
  (str "Hello, " name))
`
	if err := os.WriteFile(filepath.Join(dir, "utils.clj"), []byte(src), 0o600); err != nil {
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
	if a.Name() != "clojure" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "clojure")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	content := `{:deps {org.clojure/clojure {:mvn/version "1.11.1"}
         clj-http/clj-http {:mvn/version "3.12.3"}
         ring/ring-core {:mvn/version "1.11.0"}}}
`
	if err := os.WriteFile(filepath.Join(dir, "deps.edn"), []byte(content), 0o600); err != nil {
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

	// Root module + at least 3 deps.
	if len(g.Modules) < 4 {
		t.Errorf("expected at least 4 modules, got %d", len(g.Modules))
	}

	if _, ok := g.Packages["clj-http/clj-http"]; !ok {
		t.Error("expected 'clj-http/clj-http' package in graph")
	}
	if _, ok := g.Packages["ring/ring-core"]; !ok {
		t.Error("expected 'ring/ring-core' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseDepsEdn(f *testing.F) {
	f.Add([]byte(`{:deps {org.clojure/clojure {:mvn/version "1.11.1"}}}`))
	f.Add([]byte(`{:deps {}}`))
	f.Add([]byte(``))
	f.Add([]byte(`; comment only`))
	f.Add([]byte(`{:aliases {:dev {:extra-deps {criterium {:mvn/version "0.4.6"}}}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "deps.edn"), data, 0o600); err != nil {
			return
		}
		loadDepsEdn(dir) //nolint:errcheck
	})
}
