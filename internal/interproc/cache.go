package interproc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/1homsi/gorisk/internal/ir"
)

const (
	// CacheVersion is incremented when cache format changes
	CacheVersion = "1.0.0"
)

// CacheKey uniquely identifies a function summary for caching.
type CacheKey struct {
	Function     ir.Symbol  `json:"function"`
	Context      ir.Context `json:"context"`
	DirectCaps   string     `json:"direct_caps"`   // Hash of direct capabilities
	CalleeHashes []string   `json:"callee_hashes"` // Hashes of callee summaries
	CodeHash     string     `json:"code_hash"`     // File mtime or git blob hash
}

// Hash computes a unique hash for this cache key.
func (k CacheKey) Hash() string {
	// Serialize to JSON for consistent hashing
	data, _ := json.Marshal(k)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8]) // First 8 bytes for shorter names
}

// CacheEntry stores a serialized summary.
type CacheEntry struct {
	Key       CacheKey           `json:"key"`
	Summary   ir.FunctionSummary `json:"summary"`
	Timestamp time.Time          `json:"timestamp"`
	Version   string             `json:"version"`
}

// Cache manages persistent function summaries.
type Cache struct {
	dir     string
	enabled bool
	hits    int
	misses  int
}

// NewCache creates a new cache manager.
// If dir is empty, uses $HOME/.cache/gorisk/summaries/
func NewCache(projectDir string) *Cache {
	cacheDir := os.Getenv("GORISK_CACHE_DIR")
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

// Get retrieves a cached summary if valid.
func (c *Cache) Get(key CacheKey) (ir.FunctionSummary, bool) {
	if !c.enabled {
		return ir.FunctionSummary{}, false
	}

	path := c.entryPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		c.misses++
		Debugf("[cache] MISS: %s", key.Function.String())
		return ir.FunctionSummary{}, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		c.misses++
		return ir.FunctionSummary{}, false
	}

	// Validate version
	if entry.Version != CacheVersion {
		c.misses++
		return ir.FunctionSummary{}, false
	}

	// Validate key match (code hash, callee hashes)
	if entry.Key.CodeHash != key.CodeHash {
		c.misses++
		return ir.FunctionSummary{}, false
	}

	if !slicesEqual(entry.Key.CalleeHashes, key.CalleeHashes) {
		c.misses++
		return ir.FunctionSummary{}, false
	}

	c.hits++
	Debugf("[cache] HIT: %s", key.Function.String())
	return entry.Summary, true
}

// Put stores a summary in the cache.
func (c *Cache) Put(key CacheKey, summary ir.FunctionSummary) {
	if !c.enabled {
		return
	}

	entry := CacheEntry{
		Key:       key,
		Summary:   summary,
		Timestamp: time.Now(),
		Version:   CacheVersion,
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

	// Sanitize package name for filesystem
	pkg = filepath.Clean(pkg)

	// Use hash for filename to avoid conflicts
	filename := key.Hash() + ".json"

	return filepath.Join(c.dir, pkg, filename)
}

// Stats returns cache hit/miss statistics.
func (c *Cache) Stats() (hits, misses int) {
	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total) * 100.0
	}
	if total > 0 {
		Infof("[cache] Stats: hits=%d, misses=%d, hit_rate=%.1f%%", c.hits, c.misses, hitRate)
	}
	return c.hits, c.misses
}

// Clear removes all cached entries.
func (c *Cache) Clear() error {
	if !c.enabled {
		return nil
	}
	return os.RemoveAll(c.dir)
}

// LoadOrCompute checks the cache and falls back to computation.
func LoadOrCompute(node ir.ContextNode, cg *ir.CSCallGraph, cache *Cache, computeFn func(ir.ContextNode) ir.FunctionSummary) ir.FunctionSummary {
	// Build cache key
	key := CacheKey{
		Function: node.Function,
		Context:  node.Context,
	}

	// Get direct capabilities hash
	if summary, ok := cg.Summaries[node.String()]; ok {
		key.DirectCaps = hashCapabilitySet(summary.Effects)
	}

	// Get callee hashes
	callees := cg.Edges[node.String()]
	calleeHashes := make([]string, 0, len(callees))
	for _, callee := range callees {
		if calleeSummary, ok := cg.Summaries[callee.String()]; ok {
			calleeHashes = append(calleeHashes, hashSummary(calleeSummary))
		}
	}
	sort.Strings(calleeHashes) // Sort for determinism
	key.CalleeHashes = calleeHashes

	// TODO: Add file mtime or git hash for code_hash
	key.CodeHash = "unimplemented"

	// Try to load from cache
	if summary, ok := cache.Get(key); ok {
		return summary
	}

	// Compute and cache
	summary := computeFn(node)
	cache.Put(key, summary)
	return summary
}

// hashCapabilitySet computes a hash of a capability set.
func hashCapabilitySet(caps any) string {
	data, _ := json.Marshal(caps)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8])
}

// hashSummary computes a hash of a function summary.
func hashSummary(summary ir.FunctionSummary) string {
	data, _ := json.Marshal(summary)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8])
}

// slicesEqual checks if two string slices are equal.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
