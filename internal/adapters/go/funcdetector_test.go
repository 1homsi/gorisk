package goadapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func TestDetectFunctionsExec(t *testing.T) {
	dir := t.TempDir()
	src := `package mypkg

import "os/exec"

func RunCmd() {
	exec.Command("ls", "-la")
}
`
	if err := os.WriteFile(filepath.Join(dir, "cmd.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	funcs, _, err := DetectFunctions(dir, []string{"cmd.go"})
	if err != nil {
		t.Fatal(err)
	}

	fc, ok := funcs[".RunCmd"]
	if !ok {
		t.Fatalf("expected .RunCmd in funcs, got keys: %v", funcKeys(funcs))
	}
	if !fc.DirectCaps.Has(capability.CapExec) {
		t.Errorf("expected CapExec in RunCmd.DirectCaps, got: %v", fc.DirectCaps.List())
	}
	evs := fc.DirectCaps.Evidence[capability.CapExec]
	for _, ev := range evs {
		if ev.Via == "callSite" && ev.Confidence == 0.75 {
			return
		}
	}
	t.Errorf("expected callSite evidence with confidence=0.75, got: %+v", evs)
}

func TestDetectFunctionsNetwork(t *testing.T) {
	dir := t.TempDir()
	src := `package mypkg

import "net/http"

func Fetch(url string) {
	http.Get(url)
}
`
	if err := os.WriteFile(filepath.Join(dir, "fetch.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	funcs, _, err := DetectFunctions(dir, []string{"fetch.go"})
	if err != nil {
		t.Fatal(err)
	}

	fc, ok := funcs[".Fetch"]
	if !ok {
		t.Fatalf("expected .Fetch in funcs, got: %v", funcKeys(funcs))
	}
	if !fc.DirectCaps.Has(capability.CapNetwork) {
		t.Errorf("expected CapNetwork in Fetch.DirectCaps, got: %v", fc.DirectCaps.List())
	}
}

func TestDetectFunctionsCallEdges(t *testing.T) {
	dir := t.TempDir()
	src := `package mypkg

import "os/exec"

func helper() {
	exec.Command("ls")
}

func main() {
	helper()
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	_, calls, err := DetectFunctions(dir, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}

	// Should find an edge from .main → .helper
	found := false
	for _, edge := range calls {
		if edge.Caller.Name == "main" && edge.Callee.Name == "helper" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected call edge main→helper, got edges: %+v", calls)
	}
}

func TestDetectFunctionsMethod(t *testing.T) {
	dir := t.TempDir()
	src := `package mypkg

import "net/http"

type Client struct{}

func (c *Client) Do() {
	http.Get("http://example.com")
}
`
	if err := os.WriteFile(filepath.Join(dir, "client.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	funcs, _, err := DetectFunctions(dir, []string{"client.go"})
	if err != nil {
		t.Fatal(err)
	}

	// Method should appear as ".Client.Do"
	fc, ok := funcs[".Client.Do"]
	if !ok {
		t.Fatalf("expected .Client.Do in funcs, got: %v", funcKeys(funcs))
	}
	if !fc.DirectCaps.Has(capability.CapNetwork) {
		t.Errorf("expected CapNetwork in Client.Do, got: %v", fc.DirectCaps.List())
	}
}

func TestDetectFunctionsMultiFile(t *testing.T) {
	dir := t.TempDir()
	src1 := `package mypkg
import "os/exec"
func A() { exec.Command("ls") }
`
	src2 := `package mypkg
import "net/http"
func B() { http.Get("http://x.com") }
`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte(src2), 0600); err != nil {
		t.Fatal(err)
	}

	funcs, _, err := DetectFunctions(dir, []string{"a.go", "b.go"})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := funcs[".A"]; !ok {
		t.Errorf("expected .A, got: %v", funcKeys(funcs))
	}
	if _, ok := funcs[".B"]; !ok {
		t.Errorf("expected .B, got: %v", funcKeys(funcs))
	}
}

func funcKeys(funcs map[string]ir.FunctionCaps) []string {
	keys := make([]string, 0, len(funcs))
	for k := range funcs {
		keys = append(keys, k)
	}
	return keys
}
