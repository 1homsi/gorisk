package capability

import (
	"slices"
	"testing"
)

// TestImportCapabilities and TestCallCapabilities verify that the patterns
// loaded from languages/go.yaml contain the expected mappings.
// These are integration-style tests: a missing entry here means the YAML was
// accidentally edited or a capability name was misspelled.

func TestImportCapabilities(t *testing.T) {
	tests := []struct {
		importPath string
		wantCap    Capability
	}{
		{"os/exec", CapExec},
		{"net/http", CapNetwork},
		{"unsafe", CapUnsafe},
		{"reflect", CapReflect},
		{"plugin", CapPlugin},
		{"crypto/tls", CapCrypto},
	}

	for _, tt := range tests {
		caps := ImportCapabilities(tt.importPath)
		if !slices.Contains(caps, tt.wantCap) {
			t.Errorf("import %q: expected capability %v not found in %v", tt.importPath, tt.wantCap, caps)
		}
	}
}

func TestImportCapabilitiesUnknown(t *testing.T) {
	caps := ImportCapabilities("fmt")
	if len(caps) != 0 {
		t.Errorf("fmt should have no capabilities, got %v", caps)
	}
}

func TestCallCapabilities(t *testing.T) {
	tests := []struct {
		pkg     string
		fn      string
		wantCap Capability
	}{
		{"exec", "Command", CapExec},
		{"http", "Get", CapNetwork},
		{"os", "Getenv", CapEnv},
		{"os", "WriteFile", CapFSWrite},
		{"os", "ReadFile", CapFSRead},
	}

	for _, tt := range tests {
		caps := CallCapabilities(tt.pkg, tt.fn)
		if !slices.Contains(caps, tt.wantCap) {
			t.Errorf("%s.%s: expected capability %v not found in %v", tt.pkg, tt.fn, tt.wantCap, caps)
		}
	}
}

func TestCallCapabilitiesUnknown(t *testing.T) {
	caps := CallCapabilities("fmt", "Println")
	if len(caps) != 0 {
		t.Errorf("fmt.Println should have no capabilities, got %v", caps)
	}
}

// TestLoadPatternsValidation ensures both YAML files load without error and
// that all capability names they reference are in the known taxonomy.
func TestLoadPatternsValidation(t *testing.T) {
	for _, lang := range []string{"go", "node"} {
		ps, err := LoadPatterns(lang)
		if err != nil {
			t.Errorf("LoadPatterns(%q) error: %v", lang, err)
			continue
		}
		if ps.Name != lang {
			t.Errorf("LoadPatterns(%q): name = %q, want %q", lang, ps.Name, lang)
		}
		if len(ps.Imports) == 0 {
			t.Errorf("LoadPatterns(%q): imports map is empty", lang)
		}
		if len(ps.CallSites) == 0 {
			t.Errorf("LoadPatterns(%q): call_sites map is empty", lang)
		}
	}
}

// TestLoadPatternsUnknownLang confirms a helpful error is returned for an
// unrecognised language key.
func TestLoadPatternsUnknownLang(t *testing.T) {
	_, err := LoadPatterns("cobol")
	if err == nil {
		t.Error("expected error for unknown language, got nil")
	}
}
