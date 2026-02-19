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

// nodePatterns is the Node.js PatternSet loaded from languages/node.yaml.
var nodePatterns = capability.MustLoadPatterns("node")

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
			if info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".js", ".ts", ".tsx", ".mjs", ".cjs":
			if astCaps, err := DetectFileAST(path); err == nil {
				caps.MergeWithEvidence(astCaps)
			} else {
				scanFile(path, &caps)
			}
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
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		for _, m := range reRequire.FindAllStringSubmatch(line, -1) {
			importPath := m[1]
			for _, c := range nodePatterns.Imports[importPath] {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    m[0],
					Via:        "import",
					Confidence: 0.90,
				})
			}
		}
		for _, m := range reImportFrom.FindAllStringSubmatch(line, -1) {
			importPath := m[1]
			for _, c := range nodePatterns.Imports[importPath] {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    m[0],
					Via:        "import",
					Confidence: 0.90,
				})
			}
		}
		for _, m := range reImportDyn.FindAllStringSubmatch(line, -1) {
			importPath := m[1]
			for _, c := range nodePatterns.Imports[importPath] {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    m[0],
					Via:        "import",
					Confidence: 0.90,
				})
			}
			caps.AddWithEvidence(capability.CapPlugin, capability.CapabilityEvidence{
				File:       path,
				Line:       lineNo,
				Context:    m[0],
				Via:        "import",
				Confidence: 0.90,
			})
		}

		for pattern, patCaps := range nodePatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    pattern,
						Via:        "callSite",
						Confidence: 0.60,
					})
				}
			}
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
				snippet := script
				if len(snippet) > 80 {
					snippet = snippet[:77] + "..."
				}
				ev := capability.CapabilityEvidence{
					File:       "package.json",
					Context:    scriptName + ": " + snippet,
					Via:        "installScript",
					Confidence: 0.85,
				}
				caps.AddWithEvidence(capability.CapExec, ev)
				caps.AddWithEvidence(capability.CapNetwork, ev)
				break
			}
		}
	}
}
