package capability

import (
	"slices"
	"testing"
)

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
