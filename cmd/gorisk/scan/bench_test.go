package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkScanGoProject measures scan throughput on the minimal go-simple fixture.
// Run with: go test -bench=BenchmarkScanGoProject -benchtime=5s ./cmd/gorisk/scan/
func BenchmarkScanGoProject(b *testing.B) {
	fixtureDir, err := filepath.Abs(filepath.Join("testdata", "golden", "go-simple"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := os.Stat(fixtureDir); err != nil {
		b.Skip("go-simple fixture not found")
	}

	origDir, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(fixtureDir); err != nil {
		b.Fatalf("chdir: %v", err)
	}
	b.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	// Redirect stdout to discard output during benchmark.
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		old := os.Stdout
		os.Stdout = devNull
		Run([]string{"--lang", "go"})
		os.Stdout = old
	}
}

// BenchmarkScanNodeProject measures scan throughput on the minimal node-simple fixture.
// Run with: go test -bench=BenchmarkScanNodeProject -benchtime=5s ./cmd/gorisk/scan/
func BenchmarkScanNodeProject(b *testing.B) {
	fixtureDir, err := filepath.Abs(filepath.Join("testdata", "golden", "node-simple"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := os.Stat(fixtureDir); err != nil {
		b.Skip("node-simple fixture not found")
	}

	origDir, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(fixtureDir); err != nil {
		b.Fatalf("chdir: %v", err)
	}
	b.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		old := os.Stdout
		os.Stdout = devNull
		Run([]string{"--lang", "node"})
		os.Stdout = old
	}
}
