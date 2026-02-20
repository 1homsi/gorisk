package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/graph"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected string
	}{
		{
			name:     "go project",
			files:    []string{"go.mod"},
			expected: "go",
		},
		{
			name:     "node project",
			files:    []string{"package.json"},
			expected: "node",
		},
		{
			name:     "multi project",
			files:    []string{"go.mod", "package.json"},
			expected: "multi",
		},
		{
			name:     "no markers",
			files:    []string{},
			expected: "go", // defaults to go
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			got := detect(dir)
			if got != tt.expected {
				t.Errorf("detect() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")

	// File doesn't exist
	if fileExists(testFile) {
		t.Error("fileExists() = true, want false for non-existent file")
	}

	// Create file
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	// File exists
	if !fileExists(testFile) {
		t.Error("fileExists() = false, want true for existing file")
	}
}

func TestForLang(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		lang        string
		setupFiles  []string
		expectName  string
		expectError bool
	}{
		{
			name:       "explicit go",
			lang:       "go",
			expectName: "go",
		},
		{
			name:       "explicit node",
			lang:       "node",
			expectName: "node",
		},
		{
			name:        "invalid language",
			lang:        "python",
			expectError: true,
		},
		{
			name:       "auto detect go",
			lang:       "auto",
			setupFiles: []string{"go.mod"},
			expectName: "go",
		},
		{
			name:       "auto detect node",
			lang:       "auto",
			setupFiles: []string{"package.json"},
			expectName: "node",
		},
		{
			name:       "auto detect multi",
			lang:       "auto",
			setupFiles: []string{"go.mod", "package.json"},
			expectName: "multi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join(dir, tt.name)
			if err := os.Mkdir(testDir, 0750); err != nil {
				t.Fatal(err)
			}

			for _, f := range tt.setupFiles {
				if err := os.WriteFile(filepath.Join(testDir, f), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			analyzer, err := ForLang(tt.lang, testDir)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if analyzer.Name() != tt.expectName {
				t.Errorf("analyzer.Name() = %q, want %q", analyzer.Name(), tt.expectName)
			}
		})
	}
}

func TestFeaturesFor(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		lang        string
		setupFiles  []string
		expectError bool
	}{
		{
			name: "go features",
			lang: "go",
		},
		{
			name: "node features",
			lang: "node",
		},
		{
			name:        "invalid language",
			lang:        "rust",
			expectError: true,
		},
		{
			name:       "auto detect go",
			lang:       "auto",
			setupFiles: []string{"go.mod"},
		},
		{
			name:       "auto detect multi defaults to go",
			lang:       "auto",
			setupFiles: []string{"go.mod", "package.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join(dir, tt.name)
			if err := os.Mkdir(testDir, 0750); err != nil {
				t.Fatal(err)
			}

			for _, f := range tt.setupFiles {
				if err := os.WriteFile(filepath.Join(testDir, f), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			features, err := FeaturesFor(tt.lang, testDir)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify features are not nil
			if features.Upgrade == nil {
				t.Error("Upgrade feature is nil")
			}
			if features.CapDiff == nil {
				t.Error("CapDiff feature is nil")
			}
			if features.PRDiff == nil {
				t.Error("PRDiff feature is nil")
			}
			if features.Reachability == nil {
				t.Error("Reachability feature is nil")
			}
		})
	}
}

func TestMergeGraphs(t *testing.T) {
	// Create two graphs to merge
	graphA := graph.NewDependencyGraph()
	graphA.Main = &graph.Module{Path: "moduleA", Version: "v1.0.0"}
	graphA.Modules["moduleA"] = graphA.Main
	graphA.Packages["pkgA"] = &graph.Package{ImportPath: "pkgA"}
	graphA.Edges["pkgA"] = []string{"dep1"}

	graphB := graph.NewDependencyGraph()
	graphB.Main = &graph.Module{Path: "moduleB", Version: "v2.0.0"}
	graphB.Modules["moduleB"] = graphB.Main
	graphB.Packages["pkgB"] = &graph.Package{ImportPath: "pkgB"}
	graphB.Edges["pkgB"] = []string{"dep2"}

	merged := mergeGraphs(graphA, graphB)

	// Check Main is from graphA (first graph takes precedence)
	if merged.Main.Path != "moduleA" {
		t.Errorf("merged.Main.Path = %q, want %q", merged.Main.Path, "moduleA")
	}

	// Check modules from both graphs are present
	if _, ok := merged.Modules["moduleA"]; !ok {
		t.Error("moduleA not found in merged graph")
	}
	if _, ok := merged.Modules["moduleB"]; !ok {
		t.Error("moduleB not found in merged graph")
	}

	// Check packages from both graphs are present
	if _, ok := merged.Packages["pkgA"]; !ok {
		t.Error("pkgA not found in merged graph")
	}
	if _, ok := merged.Packages["pkgB"]; !ok {
		t.Error("pkgB not found in merged graph")
	}

	// Check edges from both graphs are present
	if _, ok := merged.Edges["pkgA"]; !ok {
		t.Error("pkgA edges not found in merged graph")
	}
	if _, ok := merged.Edges["pkgB"]; !ok {
		t.Error("pkgB edges not found in merged graph")
	}
}

func TestMergeGraphsWithNilMain(t *testing.T) {
	graphA := graph.NewDependencyGraph()
	graphA.Main = nil

	graphB := graph.NewDependencyGraph()
	graphB.Main = &graph.Module{Path: "moduleB"}

	merged := mergeGraphs(graphA, graphB)

	// When graphA.Main is nil, should use graphB.Main
	if merged.Main == nil || merged.Main.Path != "moduleB" {
		t.Error("Expected merged.Main to be from graphB when graphA.Main is nil")
	}
}
