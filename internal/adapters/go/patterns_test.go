package goadapter

import (
	"slices"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

// TestImportCapabilities and TestCallCapabilities verify that the patterns
// loaded from languages/go.yaml contain the expected mappings.
// These are integration-style tests: a missing entry here means the YAML was
// accidentally edited or a capability name was misspelled.

func TestImportCapabilities(t *testing.T) {
	tests := []struct {
		importPath string
		wantCap    capability.Capability
	}{
		{"os/exec", capability.CapExec},
		{"net/http", capability.CapNetwork},
		{"unsafe", capability.CapUnsafe},
		{"reflect", capability.CapReflect},
		{"plugin", capability.CapPlugin},
		{"crypto/tls", capability.CapCrypto},
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
		wantCap capability.Capability
	}{
		{"exec", "Command", capability.CapExec},
		{"http", "Get", capability.CapNetwork},
		{"os", "Getenv", capability.CapEnv},
		{"os", "WriteFile", capability.CapFSWrite},
		{"os", "ReadFile", capability.CapFSRead},
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
