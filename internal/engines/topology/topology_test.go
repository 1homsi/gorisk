package topology

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// hasMajorVersion
// ---------------------------------------------------------------------------

func TestHasMajorVersion(t *testing.T) {
	cases := []struct {
		mod  string
		want bool
	}{
		{"github.com/foo/bar/v2", true},
		{"github.com/foo/bar/v10", true},
		{"github.com/foo/bar", false},
		{"github.com/foo/bar/v1", true}, // v1 matches the pattern (v + all digits)
		{"gopkg.in/yaml.v3", false},     // .v3 not /vN
		{"", false},
	}
	for _, tc := range cases {
		got := hasMajorVersion(tc.mod)
		if got != tc.want {
			t.Errorf("hasMajorVersion(%q) = %v, want %v", tc.mod, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// moduleBase
// ---------------------------------------------------------------------------

func TestModuleBase(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"github.com/foo/bar@v1.2.3", "github.com/foo/bar"},
		{"github.com/foo/bar/v2@v2.0.0", "github.com/foo/bar"},
		{"github.com/foo/bar", "github.com/foo/bar"},
		{"golang.org/x/tools@v0.1.0", "golang.org/x/tools"},
	}
	for _, tc := range cases {
		got := moduleBase(tc.input)
		if got != tc.want {
			t.Errorf("moduleBase(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// computeScore
// ---------------------------------------------------------------------------

func TestComputeScore_Zero(t *testing.T) {
	r := TopologyReport{
		DirectDeps:        5,
		DeepPackagePct:    10,
		MajorVersionSkew:  1,
		DuplicateVersions: 1,
		LockfileChurn:     1,
	}
	_, score := computeScore(r)
	if score != 0 {
		t.Errorf("expected 0, got %v", score)
	}
}

func TestComputeScore_MaxCap(t *testing.T) {
	r := TopologyReport{
		DirectDeps:        200,
		DeepPackagePct:    80,
		MajorVersionSkew:  10,
		DuplicateVersions: 15,
		LockfileChurn:     20,
	}
	_, score := computeScore(r)
	if score != 20 {
		t.Errorf("expected 20 (cap), got %v", score)
	}
}

func TestComputeScore_MidRange(t *testing.T) {
	r := TopologyReport{
		DirectDeps:        60, // score 5
		DeepPackagePct:    40, // score 2
		MajorVersionSkew:  5,  // score 2
		DuplicateVersions: 5,  // score 2
		LockfileChurn:     5,  // score 2
	}
	_, score := computeScore(r)
	if score != 13 {
		t.Errorf("expected 13, got %v", score)
	}
}

func TestComputeScore_NegativeChurn(t *testing.T) {
	r := TopologyReport{LockfileChurn: -1}
	_, score := computeScore(r)
	if score != 0 {
		t.Errorf("expected 0 for no-git churn, got %v", score)
	}
}

// ---------------------------------------------------------------------------
// resolveLang
// ---------------------------------------------------------------------------

func TestResolveLang_ExplicitGo(t *testing.T) {
	lang, err := resolveLang(".", "go")
	if err != nil || lang != "go" {
		t.Errorf("got %q %v", lang, err)
	}
}

func TestResolveLang_ExplicitNode(t *testing.T) {
	lang, err := resolveLang(".", "node")
	if err != nil || lang != "node" {
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

func TestResolveLang_AutoNode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0600); err != nil {
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
// parseGoMod
// ---------------------------------------------------------------------------

func TestParseGoMod_Basic(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.20.0 // indirect
)

require github.com/spf13/cobra v1.8.0
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	direct, skew, err := parseGoMod(dir)
	if err != nil {
		t.Fatal(err)
	}
	// pkg/errors is direct, x/net is indirect, cobra is direct
	if !direct["github.com/pkg/errors"] {
		t.Error("expected pkg/errors to be direct")
	}
	if direct["golang.org/x/net"] {
		t.Error("expected x/net to be indirect (not direct)")
	}
	if !direct["github.com/spf13/cobra"] {
		t.Error("expected cobra to be direct")
	}
	if skew != 0 {
		t.Errorf("expected skew 0, got %d", skew)
	}
}

func TestParseGoMod_MajorVersionSkew(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod
require (
	github.com/foo/bar/v2 v2.0.0
	github.com/foo/baz/v3 v3.1.0
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, skew, err := parseGoMod(dir)
	if err != nil {
		t.Fatal(err)
	}
	if skew != 2 {
		t.Errorf("expected skew 2, got %d", skew)
	}
}

// ---------------------------------------------------------------------------
// gitChurn (non-git dir returns -1)
// ---------------------------------------------------------------------------

func TestGitChurn_NonGitDir(t *testing.T) {
	dir := t.TempDir()
	n := gitChurn(dir, "go.mod")
	if n != -1 {
		t.Errorf("expected -1 for non-git dir, got %d", n)
	}
}
