package lua

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadLuarocksLock(t *testing.T) {
	dir := t.TempDir()

	lockContent := `locks_version = "1.0.0"

[dependencies]
  [dependencies.luasocket]
  version = "3.1.0-1"

  [dependencies.luasec]
  version = "1.3.2-1"

  [dependencies.lua-cjson]
  version = "2.1.0.10-1"
`
	rockspecContent := `package = "myapp"
version = "1.0-1"
dependencies = {
   "lua >= 5.1",
   "luasocket >= 3.0",
   "luasec >= 1.0",
}
`
	if err := os.WriteFile(filepath.Join(dir, "luarocks.lock"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "myapp-1.0-1.rockspec"), []byte(rockspecContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]LuaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["luasocket"]; !ok {
		t.Error("expected 'luasocket' in packages")
	}
	if byName["luasocket"].Version != "3.1.0-1" {
		t.Errorf("luasocket version: got %q, want %q", byName["luasocket"].Version, "3.1.0-1")
	}
	if !byName["luasocket"].Direct {
		t.Error("luasocket should be a direct dep (listed in rockspec)")
	}
	if !byName["luasec"].Direct {
		t.Error("luasec should be a direct dep (listed in rockspec)")
	}
	// lua-cjson is in lock but not rockspec, so indirect.
	if byName["lua-cjson"].Direct {
		t.Error("lua-cjson should be an indirect dep")
	}
}

func TestLoadRockspec(t *testing.T) {
	dir := t.TempDir()
	rockspecContent := `package = "myapp"
version = "1.0-1"
dependencies = {
   "lua >= 5.1",
   "luasocket >= 3.0",
   "luasec >= 1.0",
   "lua-cjson",
}
`
	if err := os.WriteFile(filepath.Join(dir, "myapp-1.0-1.rockspec"), []byte(rockspecContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]LuaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["luasocket"]; !ok {
		t.Error("expected 'luasocket' in packages")
	}
	if _, ok := byName["luasec"]; !ok {
		t.Error("expected 'luasec' in packages")
	}
	if _, ok := byName["lua-cjson"]; !ok {
		t.Error("expected 'lua-cjson' in packages")
	}
	// "lua" itself should be excluded.
	if _, ok := byName["lua"]; ok {
		t.Error("'lua' runtime should not be included as a package")
	}
	for _, p := range pkgs {
		if !p.Direct {
			t.Errorf("package %q should be Direct=true in rockspec fallback", p.Name)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Lua lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `local socket = require("socket")
local http = require("http")

local function run_cmd(cmd)
    os.execute(cmd)
end

local function get_env(key)
    return os.getenv(key)
end
`
	if err := os.WriteFile(filepath.Join(dir, "main.lua"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "exec", "env"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `local function add(a, b)
    return a + b
end

local function greet(name)
    return "Hello, " .. name
end

return { add = add, greet = greet }
`
	if err := os.WriteFile(filepath.Join(dir, "utils.lua"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter integration tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := Adapter{}
	if a.Name() != "lua" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "lua")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()
	rockspecContent := `package = "myapp"
version = "1.0-1"
dependencies = {
   "lua >= 5.1",
   "luasocket >= 3.0",
   "luasec >= 1.0",
}
`
	if err := os.WriteFile(filepath.Join(dir, "myapp-1.0-1.rockspec"), []byte(rockspecContent), 0o600); err != nil {
		t.Fatal(err)
	}

	a := Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules, got %d", len(g.Modules))
	}
	if _, ok := g.Packages["luasocket"]; !ok {
		t.Error("expected 'luasocket' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseLuarocksLock(f *testing.F) {
	f.Add([]byte("locks_version = \"1.0.0\"\n\n[dependencies]\n  [dependencies.luasocket]\n  version = \"3.1.0-1\"\n"))
	f.Add([]byte(""))
	f.Add([]byte("[dependencies]"))
	f.Add([]byte("not a lock file"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "luarocks.lock"), data, 0o600); err != nil {
			return
		}
		loadLuarocksLock(dir) //nolint:errcheck
	})
}
