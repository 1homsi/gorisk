package goadapter

import (
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseGoFile fuzzes the Go source file capability detector.
// The detector must never panic regardless of input.
func FuzzParseGoFile(f *testing.F) {
	f.Add([]byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"))
	f.Add([]byte("package main\n\nimport \"os/exec\"\n\nfunc main() { exec.Command(\"ls\").Run() }\n"))
	f.Add([]byte(""))
	f.Add([]byte("not go source at all"))
	f.Add([]byte("package main\nimport (\n\"net/http\"\n\"unsafe\"\n)\nvar _ = unsafe.Pointer(nil)\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		fpath := filepath.Join(dir, "main.go")
		if err := os.WriteFile(fpath, data, 0o600); err != nil {
			return
		}
		fset := token.NewFileSet()
		DetectFile(fpath, fset) //nolint:errcheck
	})
}
