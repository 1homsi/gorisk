package graph

import "testing"

func TestModulePathFromModGraph(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com/foo/bar@v1.2.3", "github.com/foo/bar"},
		{"github.com/foo/bar", "github.com/foo/bar"},
		{"example.com/module@v0.0.1", "example.com/module"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := modulePathFromModGraph(tt.input); got != tt.want {
			t.Errorf("modulePathFromModGraph(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEnsureModule(t *testing.T) {
	g := NewDependencyGraph()

	// nil input returns nil
	if m := ensureModule(g, nil); m != nil {
		t.Errorf("ensureModule(nil) = %v, want nil", m)
	}

	// New module is created and stored
	lm := &listModule{Path: "example.com/a", Version: "v1.0.0", Main: false}
	m := ensureModule(g, lm)
	if m == nil {
		t.Fatal("ensureModule returned nil for non-nil input")
	}
	if m.Path != "example.com/a" || m.Version != "v1.0.0" {
		t.Errorf("module fields = %+v", m)
	}
	if _, ok := g.Modules["example.com/a"]; !ok {
		t.Error("module not stored in graph")
	}

	// Calling again returns the same module (cached)
	m2 := ensureModule(g, lm)
	if m != m2 {
		t.Error("ensureModule should return the same cached module")
	}
}

func TestEnsureModuleMain(t *testing.T) {
	g := NewDependencyGraph()
	lm := &listModule{Path: "myapp", Version: "", Main: true}
	m := ensureModule(g, lm)
	if !m.Main {
		t.Error("expected Main=true")
	}
}
