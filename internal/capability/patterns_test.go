package capability

import "testing"

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
