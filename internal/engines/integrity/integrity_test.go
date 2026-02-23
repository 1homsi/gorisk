package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// computeScore
// ---------------------------------------------------------------------------

func TestComputeScore_Empty(t *testing.T) {
	score := computeScore(nil)
	if score != 0 {
		t.Errorf("expected 0, got %v", score)
	}
}

func TestComputeScore_Sum(t *testing.T) {
	v := []Violation{
		{Score: 5},
		{Score: 8},
		{Score: 2},
	}
	score := computeScore(v)
	if score != 15 {
		t.Errorf("expected 15, got %v", score)
	}
}

func TestComputeScore_Cap(t *testing.T) {
	v := []Violation{
		{Score: 8},
		{Score: 8},
		{Score: 8},
	}
	score := computeScore(v)
	if score != 20 {
		t.Errorf("expected 20 (cap), got %v", score)
	}
}

// ---------------------------------------------------------------------------
// parseReplaceLine
// ---------------------------------------------------------------------------

func TestParseReplaceLine_WithVersions(t *testing.T) {
	r := parseReplaceLine("github.com/foo/bar v1.0.0 => github.com/alt/bar v2.0.0")
	if r.old != "github.com/foo/bar" {
		t.Errorf("wrong old: %q", r.old)
	}
	if r.new != "github.com/alt/bar" {
		t.Errorf("wrong new: %q", r.new)
	}
}

func TestParseReplaceLine_NoVersions(t *testing.T) {
	r := parseReplaceLine("github.com/foo/bar => ./local/bar")
	if r.old != "github.com/foo/bar" {
		t.Errorf("wrong old: %q", r.old)
	}
	if r.new != "./local/bar" {
		t.Errorf("wrong new: %q", r.new)
	}
}

func TestParseReplaceLine_Empty(t *testing.T) {
	r := parseReplaceLine("")
	if r.old != "" {
		t.Errorf("expected empty old, got %q", r.old)
	}
}

func TestParseReplaceLine_TooShort(t *testing.T) {
	r := parseReplaceLine("foo bar")
	if r.old != "" {
		t.Errorf("expected empty for too-short input, got %q", r.old)
	}
}

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

func TestResolveLang_AutoYarnLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	lang, err := resolveLang(dir, "auto")
	if err != nil || lang != "node" {
		t.Errorf("got %q %v", lang, err)
	}
}

func TestResolveLang_AutoUnknown(t *testing.T) {
	dir := t.TempDir()
	_, err := resolveLang(dir, "auto")
	if err == nil {
		t.Error("expected error for empty dir")
	}
}

// ---------------------------------------------------------------------------
// parseGoSum
// ---------------------------------------------------------------------------

func TestParseGoSum(t *testing.T) {
	dir := t.TempDir()
	content := `github.com/pkg/errors v0.9.1 h1:abc=
github.com/pkg/errors v0.9.1/go.mod h1:def=
golang.org/x/net v0.1.0 h1:ghi=
`
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	seen, err := parseGoSum(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !seen["github.com/pkg/errors"] {
		t.Error("expected pkg/errors in go.sum")
	}
	if !seen["golang.org/x/net"] {
		t.Error("expected x/net in go.sum")
	}
}

func TestParseGoSum_Missing(t *testing.T) {
	dir := t.TempDir()
	_, err := parseGoSum(dir)
	if err == nil {
		t.Error("expected error for missing go.sum")
	}
}

// ---------------------------------------------------------------------------
// parseGoMod (integrity package version)
// ---------------------------------------------------------------------------

func TestParseGoMod_Requires(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mod

require (
	github.com/foo/bar v1.0.0
	github.com/baz/qux v2.0.0
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	requires, replaces, err := parseGoMod(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(requires) != 2 {
		t.Errorf("expected 2 requires, got %d", len(requires))
	}
	if len(replaces) != 0 {
		t.Errorf("expected 0 replaces, got %d", len(replaces))
	}
}

func TestParseGoMod_ReplaceLocal(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mod

require github.com/foo/bar v1.0.0

replace github.com/foo/bar => ./local/bar
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, replaces, err := parseGoMod(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(replaces) != 1 {
		t.Fatalf("expected 1 replace, got %d", len(replaces))
	}
	if replaces[0].new != "./local/bar" {
		t.Errorf("wrong new path: %q", replaces[0].new)
	}
}

// ---------------------------------------------------------------------------
// checkGo (via Check with lang="go")
// ---------------------------------------------------------------------------

func TestCheckGo_AllInSum(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/mod

require (
	github.com/foo/bar v1.0.0
)
`
	gosum := `github.com/foo/bar v1.0.0 h1:abc=
github.com/foo/bar v1.0.0/go.mod h1:def=
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(gosum), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Check(dir, "go")
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage != 100 {
		t.Errorf("expected 100%% coverage, got %.1f", r.Coverage)
	}
	if r.Score != 0 {
		t.Errorf("expected 0 score, got %v", r.Score)
	}
}

func TestCheckGo_MissingChecksum(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/mod

require github.com/foo/bar v1.0.0
`
	// go.sum is empty — bar has no entry
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Check(dir, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Violations) == 0 {
		t.Error("expected at least one missing_checksum violation")
	}
	if r.Violations[0].Type != "missing_checksum" {
		t.Errorf("expected missing_checksum, got %q", r.Violations[0].Type)
	}
}

func TestCheckGo_LocalReplace(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/mod

require github.com/foo/bar v1.0.0

replace github.com/foo/bar => ./local/bar
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("github.com/foo/bar v1.0.0 h1:x=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Check(dir, "go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range r.Violations {
		if v.Type == "local_replace" {
			found = true
		}
	}
	if !found {
		t.Error("expected local_replace violation")
	}
}

// ---------------------------------------------------------------------------
// checkNodePackageLock (via Check with lang="node")
// ---------------------------------------------------------------------------

func TestCheckNode_PackageLock_AllIntegrity(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "integrity": "sha512-abc123"
    },
    "node_modules/express": {
      "version": "4.18.0",
      "integrity": "sha512-def456"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Check(dir, "node")
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage != 100 {
		t.Errorf("expected 100%% coverage, got %.1f", r.Coverage)
	}
	if len(r.Violations) != 0 {
		t.Errorf("expected no violations, got %d", len(r.Violations))
	}
}

func TestCheckNode_PackageLock_MissingIntegrity(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/bad-pkg": {
      "version": "1.0.0"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Check(dir, "node")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Violations) == 0 {
		t.Error("expected missing_integrity violation")
	}
	if r.Violations[0].Type != "missing_integrity" {
		t.Errorf("expected missing_integrity, got %q", r.Violations[0].Type)
	}
}

func TestCheckNode_PackageLock_PathDep(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/local-pkg": {
      "version": "1.0.0",
      "integrity": "sha512-abc",
      "resolved": "file:../local-pkg"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Check(dir, "node")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range r.Violations {
		if v.Type == "path_dep" {
			found = true
		}
	}
	if !found {
		t.Error("expected path_dep violation")
	}
}

// ---------------------------------------------------------------------------
// checkYarnLock
// ---------------------------------------------------------------------------

func TestCheckYarnLock_Clean(t *testing.T) {
	dir := t.TempDir()
	content := `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
  integrity sha512-xyz

express@^4.18.0:
  version "4.18.0"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.0.tgz#def"
  integrity sha512-uvw
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := checkYarnLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalPackages != 2 {
		t.Errorf("expected 2 packages, got %d", r.TotalPackages)
	}
	if len(r.Violations) != 0 {
		t.Errorf("expected no violations, got %d", len(r.Violations))
	}
}

func TestCheckYarnLock_GitDep(t *testing.T) {
	dir := t.TempDir()
	content := `# yarn lockfile v1

my-pkg@git+https://github.com/org/my-pkg.git:
  version "1.0.0"
  resolved "git+https://github.com/org/my-pkg.git#abc123"
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := checkYarnLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range r.Violations {
		if v.Type == "git_dep" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected git_dep violation, got violations: %v", r.Violations)
	}
}

// ---------------------------------------------------------------------------
// checkPnpmLock
// ---------------------------------------------------------------------------

func TestCheckPnpmLock_Clean(t *testing.T) {
	dir := t.TempDir()
	content := `lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
    dev: false
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := checkPnpmLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage != 100 {
		t.Errorf("expected 100%% coverage (pnpm CAS), got %.1f", r.Coverage)
	}
	if len(r.Violations) != 0 {
		t.Errorf("expected no violations, got %d", len(r.Violations))
	}
}

func TestCheckPnpmLock_PathDep(t *testing.T) {
	dir := t.TempDir()
	content := `lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      my-local:
        specifier: file:../my-local
        version: file:../my-local

packages:
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := checkPnpmLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range r.Violations {
		if v.Type == "path_dep" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected path_dep violation, got: %v", r.Violations)
	}
}
