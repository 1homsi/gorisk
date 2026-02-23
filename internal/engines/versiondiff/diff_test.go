package versiondiff

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// resolveLang
// ---------------------------------------------------------------------------

func TestResolveLang_Explicit(t *testing.T) {
	lang, err := resolveLang(".", "go")
	if err != nil || lang != "go" {
		t.Errorf("got %q %v", lang, err)
	}
}

func TestResolveLang_AutoGoMod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lang, err := resolveLang(dir, "auto")
	if err != nil || lang != "go" {
		t.Errorf("got %q %v", lang, err)
	}
}

func TestResolveLang_AutoPnpm(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '6.0'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lang, err := resolveLang(dir, "auto")
	if err != nil || lang != "node" {
		t.Errorf("got %q %v", lang, err)
	}
}

// ---------------------------------------------------------------------------
// readGoModRequiresFromBytes
// ---------------------------------------------------------------------------

func TestReadGoModRequiresFromBytes_Block(t *testing.T) {
	data := []byte(`module example.com/mod

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.20.0 // indirect
)
`)
	mods, err := readGoModRequiresFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if mods["github.com/pkg/errors"] != "v0.9.1" {
		t.Errorf("wrong version for pkg/errors: %q", mods["github.com/pkg/errors"])
	}
	if mods["golang.org/x/net"] != "v0.20.0" {
		t.Errorf("wrong version for x/net: %q", mods["golang.org/x/net"])
	}
}

func TestReadGoModRequiresFromBytes_SingleLine(t *testing.T) {
	data := []byte(`module example.com/mod

require github.com/spf13/cobra v1.8.0
`)
	mods, err := readGoModRequiresFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if mods["github.com/spf13/cobra"] != "v1.8.0" {
		t.Errorf("wrong version: %q", mods["github.com/spf13/cobra"])
	}
}

// ---------------------------------------------------------------------------
// readPnpmPackagesFromBytes
// ---------------------------------------------------------------------------

func TestReadPnpmPackagesFromBytes_V6(t *testing.T) {
	data := []byte(`lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}

  /@babel/core@7.24.0:
    resolution: {integrity: sha512-def}
`)
	pkgs, err := readPnpmPackagesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if pkgs["lodash"] != "4.17.21" {
		t.Errorf("expected lodash@4.17.21, got %q", pkgs["lodash"])
	}
	if pkgs["@babel/core"] != "7.24.0" {
		t.Errorf("expected @babel/core@7.24.0, got %q", pkgs["@babel/core"])
	}
}

func TestReadPnpmPackagesFromBytes_V9(t *testing.T) {
	data := []byte(`lockfileVersion: '9.0'

snapshots:

  lodash@4.17.21:
    resolution: {integrity: sha512-abc}
`)
	pkgs, err := readPnpmPackagesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if pkgs["lodash"] != "4.17.21" {
		t.Errorf("expected lodash@4.17.21, got %q", pkgs["lodash"])
	}
}

func TestReadPnpmPackagesFromBytes_PeerDepStripped(t *testing.T) {
	// Peer dep suffix only with one @-version in entry; simple case.
	data := []byte(`lockfileVersion: '6.0'

packages:

  /eslint-plugin@1.0.0(peer-only):
    resolution: {integrity: sha512-x}
`)
	pkgs, err := readPnpmPackagesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	// The entry "eslint-plugin@1.0.0(peer-only)" has no second @, so LastIndex
	// finds the right one; peer suffix has no '(' in ver because '(' is in 'peer-only'.
	// The version stored will be "1.0.0" after stripping "(peer-only)".
	if pkgs["eslint-plugin"] != "1.0.0" {
		t.Errorf("expected 1.0.0 after peer-dep strip, got %q", pkgs["eslint-plugin"])
	}
}

// ---------------------------------------------------------------------------
// readYarnPackagesFromBytes
// ---------------------------------------------------------------------------

func TestReadYarnPackagesFromBytes(t *testing.T) {
	data := []byte(`# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"

"@babel/core@^7.24.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#def"
`)
	pkgs, err := readYarnPackagesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if pkgs["lodash"] != "4.17.21" {
		t.Errorf("expected lodash@4.17.21, got %q", pkgs["lodash"])
	}
	if pkgs["@babel/core"] != "7.24.0" {
		t.Errorf("expected @babel/core@7.24.0, got %q", pkgs["@babel/core"])
	}
}

// ---------------------------------------------------------------------------
// readNodePackagesFromBytes
// ---------------------------------------------------------------------------

func TestReadNodePackagesFromBytes_V2(t *testing.T) {
	data := []byte(`{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/express": {"version": "4.18.0"},
    "": {"version": "1.0.0"}
  }
}`)
	pkgs, err := readNodePackagesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if pkgs["lodash"] != "4.17.21" {
		t.Errorf("wrong version for lodash: %q", pkgs["lodash"])
	}
	if pkgs["express"] != "4.18.0" {
		t.Errorf("wrong version for express: %q", pkgs["express"])
	}
	// root entry "" should be excluded
	if _, ok := pkgs[""]; ok {
		t.Error("root entry should be excluded")
	}
}

func TestReadNodePackagesFromBytes_V1(t *testing.T) {
	data := []byte(`{
  "dependencies": {
    "lodash": {"version": "4.17.21"},
    "express": {"version": "4.18.0"}
  }
}`)
	pkgs, err := readNodePackagesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if pkgs["lodash"] != "4.17.21" {
		t.Errorf("wrong version for lodash: %q", pkgs["lodash"])
	}
}

// ---------------------------------------------------------------------------
// inferGoCaps
// ---------------------------------------------------------------------------

func TestInferGoCaps(t *testing.T) {
	cases := []struct {
		mod      string
		contains string
	}{
		{"github.com/creack/pty", ""},            // no known cap
		{"github.com/user/nethttp", "network"},   // net → network
		{"github.com/user/executil", "exec"},     // exec → exec
		{"github.com/user/cryptoutil", "crypto"}, // crypto
		{"golang.org/x/net/http2", "network"},    // net
	}
	for _, tc := range cases {
		caps := inferGoCaps(tc.mod)
		if tc.contains == "" {
			continue
		}
		found := false
		for _, c := range caps {
			if c == tc.contains {
				found = true
			}
		}
		if !found {
			t.Errorf("inferGoCaps(%q): expected %q in %v", tc.mod, tc.contains, caps)
		}
	}
}

// ---------------------------------------------------------------------------
// inferNodeCaps
// ---------------------------------------------------------------------------

func TestInferNodeCaps(t *testing.T) {
	cases := []struct {
		name     string
		contains string
	}{
		{"node-fetch", "network"},
		{"child_process", ""}, // doesn't match 'exec'/'spawn'/'shell' exactly
		{"shelljs", "exec"},
		{"crypto-js", "crypto"},
		{"fs-extra", "fs:read"},
		{"axios", "network"},
	}
	for _, tc := range cases {
		caps := inferNodeCaps(tc.name)
		if tc.contains == "" {
			continue
		}
		found := false
		for _, c := range caps {
			if c == tc.contains {
				found = true
			}
		}
		if !found {
			t.Errorf("inferNodeCaps(%q): expected %q in %v", tc.name, tc.contains, caps)
		}
	}
}

// ---------------------------------------------------------------------------
// capsToLevel / riskVal / levelDelta
// ---------------------------------------------------------------------------

func TestCapsToLevel(t *testing.T) {
	if l := capsToLevel([]string{"exec"}); l != "HIGH" {
		t.Errorf("exec → %q, want HIGH", l)
	}
	if l := capsToLevel([]string{"network"}); l != "MEDIUM" {
		t.Errorf("network → %q, want MEDIUM", l)
	}
	if l := capsToLevel(nil); l != "LOW" {
		t.Errorf("nil → %q, want LOW", l)
	}
	if l := capsToLevel([]string{"crypto"}); l != "MEDIUM" {
		t.Errorf("crypto → %q, want MEDIUM", l)
	}
}

func TestRiskVal(t *testing.T) {
	if riskVal("HIGH") != 2 {
		t.Error("HIGH should be 2")
	}
	if riskVal("MEDIUM") != 1 {
		t.Error("MEDIUM should be 1")
	}
	if riskVal("LOW") != 0 {
		t.Error("LOW should be 0")
	}
}

func TestLevelDelta(t *testing.T) {
	if levelDelta("HIGH", "") != 15 {
		t.Error("HIGH delta should be 15")
	}
	if levelDelta("MEDIUM", "") != 8 {
		t.Error("MEDIUM delta should be 8")
	}
	if levelDelta("LOW", "") != 0 {
		t.Error("LOW delta should be 0")
	}
}

// ---------------------------------------------------------------------------
// computeScore (DiffReport)
// ---------------------------------------------------------------------------

func TestComputeScore_Empty(t *testing.T) {
	r := DiffReport{}
	s := computeScore(r)
	if s != 0 {
		t.Errorf("expected 0, got %v", s)
	}
}

func TestComputeScore_NewPackages(t *testing.T) {
	r := DiffReport{
		NewPackages: []PackageDiff{
			{RiskDelta: 15},
			{RiskDelta: 8},
		},
	}
	s := computeScore(r)
	if s != 20 { // 23 capped at 20
		t.Errorf("expected 20 (cap), got %v", s)
	}
}

// ---------------------------------------------------------------------------
// Compute with empty base returns zero score
// ---------------------------------------------------------------------------

func TestCompute_EmptyBase(t *testing.T) {
	r, err := Compute(".", "", "go")
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != 0 {
		t.Errorf("expected 0 for empty base, got %v", r.Score)
	}
}

// ---------------------------------------------------------------------------
// detectNodeLockfile
// ---------------------------------------------------------------------------

func TestDetectNodeLockfile_PackageLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	name, reader, err := detectNodeLockfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if name != "package-lock.json" {
		t.Errorf("expected package-lock.json, got %q", name)
	}
	if reader == nil {
		t.Error("expected non-nil reader")
	}
}

func TestDetectNodeLockfile_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, _, err := detectNodeLockfile(dir)
	if err == nil {
		t.Error("expected error for missing lockfile")
	}
}

// ---------------------------------------------------------------------------
// nodePackagesFromBytes dispatch
// ---------------------------------------------------------------------------

func TestNodePackagesFromBytes_Pnpm(t *testing.T) {
	data := []byte(`lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
`)
	pkgs, err := nodePackagesFromBytes("pnpm-lock.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if pkgs["lodash"] != "4.17.21" {
		t.Errorf("expected lodash@4.17.21, got %q", pkgs["lodash"])
	}
}
