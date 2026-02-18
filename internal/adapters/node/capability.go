package node

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

var (
	reRequire    = regexp.MustCompile(`require\(['"]([^'"]+)['"]\)`)
	reImportFrom = regexp.MustCompile(`from\s+['"]([^'"]+)['"]`)
	reImportDyn  = regexp.MustCompile(`import\(['"]([^'"]+)['"]\)`)
)

// Detect scans JS/TS source files in dir and returns the combined capability set.
// It also checks package.json install scripts for network/exec patterns.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	checkInstallScripts(dir, &caps)

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			// Skip nested node_modules to avoid scanning transitive deps twice
			if info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".js", ".ts", ".tsx", ".mjs", ".cjs":
			scanFile(path, &caps)
		}
		return nil
	})

	return caps
}

func scanFile(path string, caps *capability.CapabilitySet) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Increase buffer for long minified lines
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		for _, m := range reRequire.FindAllStringSubmatch(line, -1) {
			applyImportCaps(m[1], caps)
		}
		for _, m := range reImportFrom.FindAllStringSubmatch(line, -1) {
			applyImportCaps(m[1], caps)
		}
		for _, m := range reImportDyn.FindAllStringSubmatch(line, -1) {
			applyImportCaps(m[1], caps)
			caps.Add(capability.CapPlugin)
		}

		for pattern, patCaps := range callPatterns {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.Add(c)
				}
			}
		}
	}
}

func applyImportCaps(importPath string, caps *capability.CapabilitySet) {
	if capList, ok := importPatterns[importPath]; ok {
		for _, c := range capList {
			caps.Add(c)
		}
	}
}

func checkInstallScripts(dir string, caps *capability.CapabilitySet) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return
	}
	var pkgJSON struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &pkgJSON) != nil {
		return
	}
	for _, scriptName := range []string{"preinstall", "install", "postinstall"} {
		script, ok := pkgJSON.Scripts[scriptName]
		if !ok {
			continue
		}
		lower := strings.ToLower(script)
		for _, kw := range []string{"curl", "wget", "bash", "sh ", "/bin/sh"} {
			if strings.Contains(lower, kw) {
				caps.Add(capability.CapExec)
				caps.Add(capability.CapNetwork)
				break
			}
		}
	}
}
