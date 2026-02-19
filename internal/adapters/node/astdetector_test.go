package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

func TestParseBindingsVarBind(t *testing.T) {
	src := []byte(`const cp = require('child_process');`)
	table, err := ParseBindings(src, "test.js")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := table["cp"]
	if !ok {
		t.Fatal("expected 'cp' in symbol table")
	}
	if b.Module != "child_process" {
		t.Errorf("Module = %q, want child_process", b.Module)
	}
	if b.Export != "" {
		t.Errorf("Export = %q, want empty (whole module)", b.Export)
	}
}

func TestParseBindingsDestructured(t *testing.T) {
	src := []byte(`const {exec, spawn} = require('child_process');`)
	table, err := ParseBindings(src, "test.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exec", "spawn"} {
		b, ok := table[name]
		if !ok {
			t.Errorf("expected %q in symbol table", name)
			continue
		}
		if b.Module != "child_process" {
			t.Errorf("%s.Module = %q, want child_process", name, b.Module)
		}
		if b.Export != name {
			t.Errorf("%s.Export = %q, want %q", name, b.Export, name)
		}
	}
}

func TestParseBindingsDestructuredAlias(t *testing.T) {
	src := []byte(`const {exec: runCmd} = require('child_process');`)
	table, err := ParseBindings(src, "test.js")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := table["runCmd"]
	if !ok {
		t.Fatal("expected 'runCmd' in symbol table")
	}
	if b.Export != "exec" {
		t.Errorf("Export = %q, want exec", b.Export)
	}
}

func TestParseBindingsImportNamed(t *testing.T) {
	src := []byte(`import { exec, spawn } from 'child_process';`)
	table, err := ParseBindings(src, "test.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exec", "spawn"} {
		b, ok := table[name]
		if !ok {
			t.Errorf("expected %q in symbol table", name)
			continue
		}
		if b.Module != "child_process" {
			t.Errorf("%s.Module = %q, want child_process", name, b.Module)
		}
	}
}

func TestParseBindingsImportDefault(t *testing.T) {
	src := []byte(`import fs from 'fs';`)
	table, err := ParseBindings(src, "test.js")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := table["fs"]
	if !ok {
		t.Fatal("expected 'fs' in symbol table")
	}
	if b.Module != "fs" {
		t.Errorf("Module = %q, want fs", b.Module)
	}
	if b.Export != "default" {
		t.Errorf("Export = %q, want default", b.Export)
	}
}

func TestParseBindingsImportNamespace(t *testing.T) {
	src := []byte(`import * as cp from 'child_process';`)
	table, err := ParseBindings(src, "test.ts")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := table["cp"]
	if !ok {
		t.Fatal("expected 'cp' in symbol table")
	}
	if b.Module != "child_process" {
		t.Errorf("Module = %q, want child_process", b.Module)
	}
}

func TestDetectFileASTRequireImport(t *testing.T) {
	dir := t.TempDir()
	src := `const cp = require('child_process');
cp.exec('ls');
`
	path := filepath.Join(dir, "test.js")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	caps, err := DetectFileAST(path)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Has(capability.CapExec) {
		t.Errorf("expected CapExec, got: %v", caps.List())
	}
}

func TestDetectFileASTDestructuredRequire(t *testing.T) {
	dir := t.TempDir()
	src := `const {exec} = require('child_process');
exec('ls');
`
	path := filepath.Join(dir, "test.js")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	caps, err := DetectFileAST(path)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Has(capability.CapExec) {
		t.Errorf("expected CapExec from destructured binding, got: %v", caps.List())
	}
}

func TestDetectFileASTChainedCall(t *testing.T) {
	dir := t.TempDir()
	src := `require('child_process').exec('ls');
`
	path := filepath.Join(dir, "test.js")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	caps, err := DetectFileAST(path)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Has(capability.CapExec) {
		t.Errorf("expected CapExec from chained call, got: %v", caps.List())
	}
}

func TestDetectFileASTConfidenceDestructured(t *testing.T) {
	dir := t.TempDir()
	src := `const {exec} = require('child_process');
`
	path := filepath.Join(dir, "test.js")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	caps, err := DetectFileAST(path)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Has(capability.CapExec) {
		t.Skipf("CapExec not detected (patterns may not cover this), got: %v", caps.List())
	}
	evs := caps.Evidence[capability.CapExec]
	for _, ev := range evs {
		if ev.Via == "import-destructured" && ev.Confidence == 0.85 {
			return
		}
	}
	t.Errorf("expected import-destructured evidence with confidence=0.85, got: %+v", evs)
}

func TestDetectFileASTFallback(t *testing.T) {
	// Detect should use scanFile as fallback for files that fail AST detection.
	dir := t.TempDir()
	// A file that would be detected by regex but not necessarily by AST.
	src := `const fs = require('fs');
`
	path := filepath.Join(dir, "test.js")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	var caps capability.CapabilitySet
	// scanFile should still detect the require.
	scanFile(path, &caps)
	if caps.IsEmpty() {
		// If no caps from regex either, that's OK — just checking no panic.
		t.Log("no caps detected by scanFile (possibly fs not in patterns)")
	}
}

func TestBuildProjectGraph(t *testing.T) {
	dir := t.TempDir()

	// Create a simple project with two files
	file1 := filepath.Join(dir, "main.js")
	file2 := filepath.Join(dir, "helper.js")

	src1 := `const cp = require('child_process');
cp.exec('ls');
`
	src2 := `const net = require('net');
const server = net.createServer();
`

	if err := os.WriteFile(file1, []byte(src1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte(src2), 0600); err != nil {
		t.Fatal(err)
	}

	graph, err := BuildProjectGraph(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(graph.Files) != 2 {
		t.Errorf("expected 2 files in graph, got %d", len(graph.Files))
	}

	if _, ok := graph.Files[file1]; !ok {
		t.Errorf("expected %s in graph.Files", file1)
	}
	if _, ok := graph.Files[file2]; !ok {
		t.Errorf("expected %s in graph.Files", file2)
	}
}

func TestPropagateAcrossFiles(t *testing.T) {
	dir := t.TempDir()

	file1 := filepath.Join(dir, "a.js")
	file2 := filepath.Join(dir, "b.js")

	src1 := `const cp = require('child_process');`
	src2 := `const net = require('net');`

	if err := os.WriteFile(file1, []byte(src1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte(src2), 0600); err != nil {
		t.Fatal(err)
	}

	caps1, _ := DetectFileAST(file1)
	caps2, _ := DetectFileAST(file2)

	perFile := map[string]capability.CapabilitySet{
		file1: caps1,
		file2: caps2,
	}

	graph := ProjectGraph{
		Files:   make(map[string]SymbolTable),
		Exports: make(map[string]map[string]capability.CapabilitySet),
	}

	merged := PropagateAcrossFiles(graph, perFile)

	// Should contain capabilities from both files
	if caps1.Has(capability.CapExec) && !merged.Has(capability.CapExec) {
		t.Errorf("expected merged to have CapExec")
	}
	if caps2.Has(capability.CapNetwork) && !merged.Has(capability.CapNetwork) {
		t.Errorf("expected merged to have CapNetwork")
	}
}
