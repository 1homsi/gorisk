package interproc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

func makeCacheKey(pkg, name string) CacheKey {
	return CacheKey{
		Function:   ir.Symbol{Package: pkg, Name: name, Kind: "func"},
		DirectCaps: "exec",
		CodeHash:   "abc123",
	}
}

func TestCacheKeyHash(t *testing.T) {
	k := makeCacheKey("mypkg", "Run")
	h := k.Hash()
	if len(h) != 16 {
		t.Errorf("expected 16-char hash, got %q (len=%d)", h, len(h))
	}
	// Hash is deterministic
	if h != k.Hash() {
		t.Error("Hash is not deterministic")
	}
	// Different key produces different hash
	k2 := makeCacheKey("mypkg", "Other")
	if k.Hash() == k2.Hash() {
		t.Error("different keys should produce different hashes")
	}
}

func TestCacheKeyHashWithCalleeHashes(t *testing.T) {
	k := CacheKey{
		Function:     ir.Symbol{Package: "p", Name: "f", Kind: "func"},
		CalleeHashes: []string{"hash1", "hash2"},
	}
	h := k.Hash()
	if len(h) != 16 {
		t.Errorf("expected 16-char hash, got len %d", len(h))
	}
}

func TestNewCacheDisabled(t *testing.T) {
	c := NewCacheDisabled()
	if c == nil {
		t.Fatal("NewCacheDisabled returned nil")
	}
	if c.enabled {
		t.Error("expected disabled cache")
	}
	// Load on disabled cache always misses
	k := makeCacheKey("p", "f")
	_, ok := c.Load(k)
	if ok {
		t.Error("disabled cache should always miss")
	}
	// Store on disabled cache is no-op
	c.Store(k, ir.FunctionSummary{})
	// Stats on disabled cache does nothing
	c.Stats()
}

func TestNewCacheWithDir(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	if c == nil {
		t.Fatal("NewCache returned nil")
	}
	if !c.enabled {
		t.Error("expected enabled cache")
	}
}

func TestNewCacheDefaultDir(t *testing.T) {
	// Empty dir should use default (~/.cache/gorisk/summaries)
	c := NewCache("")
	// May succeed or fail depending on home dir availability, just don't panic
	if c == nil {
		t.Fatal("NewCache returned nil")
	}
}

func TestCacheStoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)

	k := makeCacheKey("mypkg", "Run")
	summary := ir.FunctionSummary{Depth: 2, Confidence: 0.85}
	summary.Effects.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
		Context:    "test",
		Via:        "callSite",
		Confidence: 0.75,
	})

	// Miss before store
	_, ok := c.Load(k)
	if ok {
		t.Error("expected cache miss before store")
	}

	// Store and load
	c.Store(k, summary)
	loaded, ok := c.Load(k)
	if !ok {
		t.Fatal("expected cache hit after store")
	}
	if loaded.Depth != summary.Depth {
		t.Errorf("loaded depth = %d, want %d", loaded.Depth, summary.Depth)
	}
	if loaded.Confidence != summary.Confidence {
		t.Errorf("loaded confidence = %.2f, want %.2f", loaded.Confidence, summary.Confidence)
	}
}

func TestCacheStats(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)

	k := makeCacheKey("mypkg", "fn")
	// Create a miss
	c.Load(k)
	// Create a hit
	c.Store(k, ir.FunctionSummary{})
	c.Load(k)

	// Stats should not panic
	c.Stats()
}

func TestCacheStatsZeroTotal(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	// No loads/stores - Stats should be a no-op
	c.Stats()
}

// ── ComputeCodeHash ───────────────────────────────────────────────────────────

func TestComputeCodeHashEmpty(t *testing.T) {
	h := ComputeCodeHash(t.TempDir(), nil)
	if h != "" {
		t.Errorf("expected empty hash for nil files, got %q", h)
	}
}

func TestComputeCodeHashDeterministic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package main\nfunc Foo(){}"), 0600); err != nil {
		t.Fatal(err)
	}

	h1 := ComputeCodeHash(dir, []string{"a.go", "b.go"})
	h2 := ComputeCodeHash(dir, []string{"b.go", "a.go"}) // different order → same result (sorted)
	if h1 != h2 {
		t.Errorf("hash not deterministic across file orderings: %q vs %q", h1, h2)
	}
	if len(h1) != 16 {
		t.Errorf("expected 16-char hash, got %q (len=%d)", h1, len(h1))
	}
}

func TestComputeCodeHashChanges(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(fpath, []byte("package main\nfunc A(){}"), 0600); err != nil {
		t.Fatal(err)
	}
	h1 := ComputeCodeHash(dir, []string{"main.go"})

	// Modify the file
	if err := os.WriteFile(fpath, []byte("package main\nfunc A(){}\nfunc B(){}"), 0600); err != nil {
		t.Fatal(err)
	}
	h2 := ComputeCodeHash(dir, []string{"main.go"})
	if h1 == h2 {
		t.Error("hash should change when file content changes")
	}
}

func TestComputeCodeHashMissingFile(t *testing.T) {
	// A missing file should not panic; its content is skipped.
	h := ComputeCodeHash(t.TempDir(), []string{"nonexistent.go"})
	// Should still produce a non-empty hash (based on filename)
	if len(h) != 16 {
		t.Errorf("expected 16-char hash even for missing files, got %q", h)
	}
}

func TestCacheLocalPackage(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)

	// Key with empty Package should use "local"
	k := CacheKey{
		Function: ir.Symbol{Package: "", Name: "main", Kind: "func"},
		CodeHash: "xyz",
	}
	c.Store(k, ir.FunctionSummary{Depth: 1})
	loaded, ok := c.Load(k)
	if !ok {
		t.Fatal("expected cache hit for local package")
	}
	if loaded.Depth != 1 {
		t.Errorf("loaded depth = %d, want 1", loaded.Depth)
	}
}
