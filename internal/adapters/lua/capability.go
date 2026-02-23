package lua

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// luaPatterns holds the Lua PatternSet loaded from languages/lua.yaml.
var luaPatterns = capability.MustLoadPatterns("lua")

// reRequire matches require("module") or require('module') calls.
var reRequire = regexp.MustCompile(`require\s*\(\s*["']([^"']+)["']\s*\)`)

// Detect walks .lua files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".lua" {
			scanLuaFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanLuaFile scans a single Lua source file for capability evidence.
func scanLuaFile(path string, caps *capability.CapabilitySet) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		// 1. Detect require("module") — confidence 0.90.
		if matches := reRequire.FindAllStringSubmatch(line, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) < 2 {
					continue
				}
				modName := m[1]
				if importCaps, ok := luaPatterns.Imports[modName]; ok {
					for _, c := range importCaps {
						caps.AddWithEvidence(c, capability.CapabilityEvidence{
							File:       path,
							Line:       lineNo,
							Context:    strings.TrimSpace(line),
							Via:        "import",
							Confidence: 0.90,
						})
					}
				}
			}
		}

		// 2. Call-site substring patterns — confidence 0.75.
		for pattern, patCaps := range luaPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    strings.TrimSpace(line),
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}
