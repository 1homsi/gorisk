package goadapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
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
	if !cs.Has(capability.CapExec) {
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
	if !cs.Has(capability.CapNetwork) {
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
	if !cs.Has(capability.CapUnsafe) {
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

func TestDetectFileEvidenceImport(t *testing.T) {
	src := `package main
import "os/exec"
func run() {}
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	evs := cs.Evidence["exec"]
	if len(evs) == 0 {
		t.Fatal("expected at least one evidence entry for exec via import")
	}
	found := false
	for _, ev := range evs {
		if ev.Via == "import" && ev.Confidence == 0.90 && ev.Line > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected import evidence with confidence=0.90, got: %+v", evs)
	}
}

func TestDetectFileEvidenceCallSite(t *testing.T) {
	src := `package main
import "os/exec"
func run() { exec.Command("ls") }
`
	path := writeTempGoFile(t, src)
	cs, err := DetectFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	evs := cs.Evidence["exec"]

	foundCallSite := false
	for _, ev := range evs {
		if ev.Via == "callSite" && ev.Confidence == 0.60 {
			foundCallSite = true
		}
	}
	if !foundCallSite {
		t.Errorf("expected callSite evidence with confidence=0.60, got: %+v", evs)
	}
}

func TestDetectPackageMergesEvidence(t *testing.T) {
	dir := t.TempDir()
	src1 := `package main
import "os/exec"
func run() {}
`
	src2 := `package main
import "net/http"
func fetch() {}
`
	if err := os.WriteFile(dir+"/a.go", []byte(src1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/b.go", []byte(src2), 0600); err != nil {
		t.Fatal(err)
	}

	cs, err := DetectPackage(dir, []string{"a.go", "b.go"})
	if err != nil {
		t.Fatal(err)
	}
	if !cs.Has("exec") || !cs.Has("network") {
		t.Errorf("expected exec+network, got: %v", cs.List())
	}
	if len(cs.Evidence["exec"]) == 0 {
		t.Error("expected exec evidence from a.go")
	}
	if len(cs.Evidence["network"]) == 0 {
		t.Error("expected network evidence from b.go")
	}
}
