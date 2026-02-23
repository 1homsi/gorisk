package scan

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files instead of comparing")

type goldenCase struct {
	name string
	lang string
}

var goldenCases = []goldenCase{
	{name: "go-simple", lang: "go"},
	{name: "node-simple", lang: "node"},
	{name: "php-simple", lang: "php"},
}

// captureStdout redirects os.Stdout during fn and returns what was written.
func captureStdout(fn func()) []byte {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint:errcheck
	r.Close()
	return buf.Bytes()
}

// normalizeOutput strips the non-deterministic graph checksum line so golden
// comparisons remain stable across graph implementation changes.
func normalizeOutput(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(l, "graph checksum:") {
			out = append(out, "graph checksum: <omitted>")
		} else {
			out = append(out, l)
		}
	}
	return []byte(strings.Join(out, "\n"))
}

func TestScanGolden(t *testing.T) {
	// Resolve the package directory (golden test files live relative to it).
	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range goldenCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixtureDir := filepath.Join(pkgDir, "testdata", "golden", tc.name)
			if _, err := os.Stat(fixtureDir); err != nil {
				t.Skipf("fixture %s not found: %v", tc.name, err)
			}

			// Save and restore working directory.
			origDir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(fixtureDir); err != nil {
				t.Fatalf("chdir to fixture: %v", err)
			}
			t.Cleanup(func() {
				if err := os.Chdir(origDir); err != nil {
					t.Logf("warning: could not restore working directory: %v", err)
				}
			})

			got := captureStdout(func() {
				Run([]string{"--lang", tc.lang})
			})
			got = normalizeOutput(got)

			goldenPath := filepath.Join(pkgDir, "testdata", "golden", tc.name+".txt")

			if *update {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
					t.Fatalf("mkdir golden dir: %v", err)
				}
				if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
					t.Fatalf("update golden file: %v", err)
				}
				t.Logf("updated %s", goldenPath)
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden file (run with -update flag to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output mismatch for %s\n--- want ---\n%s\n--- got ---\n%s",
					tc.name, want, got)
			}
		})
	}
}
