package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	luaadapter "github.com/1homsi/gorisk/internal/adapters/lua"
)

// reLuaRequire matches Lua require calls:
//
//	require("socket")
//	require 'luasocket'
//	local x = require("socket.http")
var reLuaRequire = regexp.MustCompile(`require\s*\(?['"]([^'"]+)['"]`)

// LuaAnalyzer implements Analyzer using Lua require import analysis.
type LuaAnalyzer struct{}

func (LuaAnalyzer) Analyze(dir string) ([]ReachabilityReport, error) {
	return analyzeLua(dir, "")
}

func (LuaAnalyzer) AnalyzeFrom(dir, entryFile string) ([]ReachabilityReport, error) {
	return analyzeLua(dir, entryFile)
}

// analyzeLua scans the project's .lua source files to determine which
// installed packages are actually used ("reachable").
func analyzeLua(dir, entryFile string) ([]ReachabilityReport, error) {
	adapter := &luaadapter.Adapter{}
	g, err := adapter.Load(dir)
	if err != nil {
		return nil, err
	}

	var imported map[string]bool
	if entryFile != "" {
		entryPath := entryFile
		if !filepath.IsAbs(entryFile) {
			entryPath = filepath.Join(dir, entryFile)
		}
		imported = collectLuaFileImports(entryPath)
	} else {
		imported = collectLuaProjectImports(dir)
	}

	reachable := resolveReachable(imported, g.Edges)

	seen := make(map[string]bool)
	var reports []ReachabilityReport

	for pkgName, pkg := range g.Packages {
		if pkg.Module != nil && pkg.Module.Main {
			continue
		}
		if pkg.Capabilities.Score == 0 {
			continue
		}
		if seen[pkgName] {
			continue
		}
		seen[pkgName] = true

		// Match package by direct name or by converting dot-notation to
		// a concatenated lowercase package name (e.g. "socket.http" → "luasocket").
		pkgReachable := reachable[pkgName]
		if !pkgReachable {
			pkgReachable = reachable[strings.ToLower(pkgName)]
		}

		reports = append(reports, ReachabilityReport{
			Package:       pkgName,
			ReachableCaps: pkg.Capabilities,
			Reachable:     pkgReachable,
		})
	}

	return reports, nil
}

// collectLuaFileImports scans a single .lua file for require calls.
func collectLuaFileImports(path string) map[string]bool {
	imported := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		return imported
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		for _, m := range reLuaRequire.FindAllStringSubmatch(line, -1) {
			collectLuaModuleName(m[1], imported)
		}
	}
	return imported
}

// collectLuaProjectImports scans all .lua files in a directory,
// excluding .git/.
func collectLuaProjectImports(dir string) map[string]bool {
	imported := make(map[string]bool)

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".lua" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			for _, m := range reLuaRequire.FindAllStringSubmatch(line, -1) {
				collectLuaModuleName(m[1], imported)
			}
		}
		return nil
	})

	return imported
}

// collectLuaModuleName adds a Lua module name and its derived package name
// variants to the imported map.
func collectLuaModuleName(name string, imported map[string]bool) {
	// Add the raw module name.
	imported[name] = true
	imported[strings.ToLower(name)] = true

	// Convert dot-notation: "socket.http" → "socket", "luasocket".
	if idx := strings.IndexByte(name, '.'); idx > 0 {
		root := name[:idx]
		imported[root] = true
		imported[strings.ToLower(root)] = true
		// Common Lua pattern: prefix "lua" + root (e.g. socket → luasocket).
		imported["lua"+strings.ToLower(root)] = true
	}
}
