package capability

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempGoFile(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tmp.go")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetectFileExec(t *testing.T) {
	src := `package main
import "os/exec"
func run() { exec.Command("ls") }
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.Has(CapExec) {
		t.Errorf("expected CapExec to be detected, got caps: %v", cs.List())
	}
}

func TestDetectFileNetwork(t *testing.T) {
	src := `package main
import "net/http"
func fetch() { http.Get("http://example.com") }
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.Has(CapNetwork) {
		t.Errorf("expected CapNetwork to be detected, got caps: %v", cs.List())
	}
}

func TestDetectFileUnsafe(t *testing.T) {
	src := `package main
import _ "unsafe"
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.Has(CapUnsafe) {
		t.Errorf("expected CapUnsafe to be detected, got caps: %v", cs.List())
	}
}

func TestDetectFileNoCaps(t *testing.T) {
	src := `package main
import "fmt"
func hello() { fmt.Println("hello") }
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Score != 0 {
		t.Errorf("expected no capabilities for fmt-only file, got: %v (score=%d)", cs.List(), cs.Score)
	}
}

func TestDetectFileRiskLevel(t *testing.T) {
	src := `package main
import (
	"os/exec"
	"unsafe"
)
func run() { exec.Command("ls") }
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.RiskLevel() != "HIGH" {
		t.Errorf("expected HIGH risk, got %s (score=%d, caps=%v)", cs.RiskLevel(), cs.Score, cs.List())
	}
}
