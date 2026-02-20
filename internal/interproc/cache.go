package interproc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/1homsi/gorisk/internal/ir"
)

// CacheKey uniquely identifies a function summary for caching.
type CacheKey struct {
	Function     ir.Symbol
	Context      ir.Context
	DirectCaps   string   // Hash of direct capabilities
	CalleeHashes []string // Hashes of callee summaries
	CodeHash     string   // File mtime or git blob hash
}

// Hash returns a stable string hash of the cache key.
func (k CacheKey) Hash() string {
	h := sha256.New()
	h.Write([]byte(k.Function.String()))
	h.Write([]byte(k.Context.Caller.String()))
	h.Write([]byte(k.DirectCaps))
	for _, ch := range k.CalleeHashes {
		h.Write([]byte(ch))
	}
	h.Write([]byte(k.CodeHash))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// CacheEntry stores a serialized function summary.
type CacheEntry struct {
	Key       CacheKey           `json:"key"`
	Summary   ir.FunctionSummary `json:"summary"`
	Timestamp time.Time          `json:"timestamp"`
	Version   string             `json:"version"` // gorisk version
}

// Cache manages persistent function summary caching.
type Cache struct {
	dir     string
	enabled bool
	mu      sync.RWMutex
	hits    int
	misses  int
}

// NewCache creates a new cache manager.
func NewCache(dir string) *Cache {
	cacheDir := dir
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return &Cache{enabled: false}
		}
		cacheDir = filepath.Join(homeDir, ".cache", "gorisk", "summaries")
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return &Cache{enabled: false}
	}

	return &Cache{
		dir:     cacheDir,
		enabled: true,
	}
}

// NewCacheDisabled creates a disabled cache (no-op).
func NewCacheDisabled() *Cache {
	return &Cache{enabled: false}
}

// Load retrieves a cached summary if available.
func (c *Cache) Load(key CacheKey) (ir.FunctionSummary, bool) {
	if !c.enabled {
		return ir.FunctionSummary{}, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.entryPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		c.mu.RUnlock()
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		c.mu.RLock()
		return ir.FunctionSummary{}, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		c.mu.RUnlock()
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		c.mu.RLock()
		return ir.FunctionSummary{}, false
	}

	// Validate cache entry
	if entry.Key.Hash() != key.Hash() {
		c.mu.RUnlock()
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		c.mu.RLock()
		return ir.FunctionSummary{}, false
	}

	c.mu.RUnlock()
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	c.mu.RLock()

	return entry.Summary, true
}

// Store saves a summary to the cache.
func (c *Cache) Store(key CacheKey, summary ir.FunctionSummary) {
	if !c.enabled {
		return
	}

	entry := CacheEntry{
		Key:       key,
		Summary:   summary,
		Timestamp: time.Now(),
		Version:   "gorisk/v2",
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}

	path := c.entryPath(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}

	_ = os.WriteFile(path, data, 0o600)
}

// entryPath returns the filesystem path for a cache entry.
func (c *Cache) entryPath(key CacheKey) string {
	// Use package and function name for directory structure
	pkg := key.Function.Package
	if pkg == "" {
		pkg = "local"
	}

	filename := fmt.Sprintf("%s_%s.json", key.Function.Name, key.Hash())
	return filepath.Join(c.dir, pkg, filename)
}

// ComputeCodeHash hashes the contents of the given files (relative to dir)
// to produce a stable cache key component. Files are hashed in sorted order
// so that adding/removing/changing any file invalidates the cache.
// Returns an empty string if no files can be read.
func ComputeCodeHash(dir string, files []string) string {
	if len(files) == 0 {
		return ""
	}

	sorted := make([]string, len(files))
	copy(sorted, files)
	sort.Strings(sorted)

	h := sha256.New()
	for _, name := range sorted {
		// Write the filename into the hash so renames are detected.
		h.Write([]byte(name))
		h.Write([]byte{0})

		fpath := filepath.Join(dir, name)
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		_, _ = io.Copy(h, f)
		f.Close()
		h.Write([]byte{0})
	}

	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// Stats logs cache hit/miss statistics.
func (c *Cache) Stats() {
	if !c.enabled {
		return
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	if total == 0 {
		return
	}

	hitRate := float64(c.hits) / float64(total) * 100
	Infof("[cache] Cache stats: %d hits, %d misses (%.1f%% hit rate)", c.hits, c.misses, hitRate)
}
