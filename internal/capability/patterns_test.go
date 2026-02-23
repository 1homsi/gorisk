package capability

import (
	"regexp"
	"slices"
	"testing"
)

// TestLoadPatternsValidation ensures both YAML files load without error and
// that all capability names they reference are in the known taxonomy.
func TestLoadPatternsValidation(t *testing.T) {
	for _, lang := range []string{"go", "node", "php"} {
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

func TestGoCallSiteKeyFormatStrict(t *testing.T) {
	ps, err := LoadPatterns("go")
	if err != nil {
		t.Fatalf("LoadPatterns(go): %v", err)
	}
	re := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$`)
	for key := range ps.CallSites {
		if !re.MatchString(key) {
			t.Errorf("go call_sites key %q is not representable as pkg.Func", key)
		}
	}
}

func TestNodeCallSiteNoBroadTokens(t *testing.T) {
	ps, err := LoadPatterns("node")
	if err != nil {
		t.Fatalf("LoadPatterns(node): %v", err)
	}
	forbidden := []string{
		"request(",
		"readFile",
		"writeFile",
		"appendFile",
		"readdir",
		"exec(",
		"execSync(",
		"execFile(",
		"execFileSync(",
		"spawn(",
		"spawnSync(",
		"fork(",
	}
	for _, pat := range forbidden {
		if _, ok := ps.CallSites[pat]; ok {
			t.Errorf("node call_sites contains forbidden broad token %q", pat)
		}
	}
}

func TestPHPCallSiteNoBroadTokens(t *testing.T) {
	ps, err := LoadPatterns("php")
	if err != nil {
		t.Fatalf("LoadPatterns(php): %v", err)
	}
	forbidden := []string{"request(", "run(", "open("}
	for _, pat := range forbidden {
		if _, ok := ps.CallSites[pat]; ok {
			t.Errorf("php call_sites contains forbidden broad token %q", pat)
		}
	}
}

func TestPatternMappingConservative(t *testing.T) {
	tests := []struct {
		lang string
		kind string
		key  string
		want []Capability
	}{
		// Go: new close-call additions
		{lang: "go", kind: "call", key: "os.Readlink", want: []Capability{CapFSRead}},
		{lang: "go", kind: "call", key: "os.Truncate", want: []Capability{CapFSWrite}},
		{lang: "go", kind: "call", key: "net.ListenPacket", want: []Capability{CapNetwork}},
		{lang: "go", kind: "call", key: "net.LookupTXT", want: []Capability{CapNetwork}},
		{lang: "go", kind: "call", key: "tls.DialWithDialer", want: []Capability{CapNetwork, CapCrypto}},
		// Node: namespaced close-call additions
		{lang: "node", kind: "call", key: "http.request(", want: []Capability{CapNetwork}},
		{lang: "node", kind: "call", key: "child_process.exec(", want: []Capability{CapExec}},
		{lang: "node", kind: "call", key: "fs.promises.readFile(", want: []Capability{CapFSRead}},
		{lang: "node", kind: "call", key: "fs.promises.writeFile(", want: []Capability{CapFSWrite}},
		{lang: "node", kind: "call", key: "module.createRequire(", want: []Capability{CapPlugin}},
		// PHP: facade close-call additions
		{lang: "php", kind: "call", key: "Http::head(", want: []Capability{CapNetwork}},
		{lang: "php", kind: "call", key: "Http::retry(", want: []Capability{CapNetwork}},
		{lang: "php", kind: "call", key: "Storage::temporaryUrl(", want: []Capability{CapNetwork}},
		{lang: "php", kind: "call", key: "Process::start(", want: []Capability{CapExec}},
	}

	for _, tt := range tests {
		ps, err := LoadPatterns(tt.lang)
		if err != nil {
			t.Fatalf("LoadPatterns(%s): %v", tt.lang, err)
		}
		var got []Capability
		switch tt.kind {
		case "call":
			got = ps.CallSites[tt.key]
		case "import":
			got = ps.Imports[tt.key]
		default:
			t.Fatalf("unknown kind %q", tt.kind)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s %s %q: got %v, want %v", tt.lang, tt.kind, tt.key, got, tt.want)
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
