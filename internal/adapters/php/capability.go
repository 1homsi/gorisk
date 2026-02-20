package php

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// phpPatterns holds the PHP PatternSet loaded from languages/php.yaml.
var phpPatterns = capability.MustLoadPatterns("php")

// Detect scans PHP source files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".php" {
			scanFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanFile scans a single PHP file for capability evidence.
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

		// Match well-known Composer package imports from `use` statements.
		// PHP use statements: "use Vendor\Package\ClassName;"
		// We derive the Composer package name from the namespace prefix.
		if checkUseStatement(line, caps, path, lineNo) {
			continue
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range phpPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    pattern,
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}

// checkUseStatement detects Composer package imports from PHP `use` statements.
// It tries an exact vendor/package match first, then falls back to any pattern
// that shares the same vendor prefix (e.g. "GuzzleHttp\" → "guzzlehttp/guzzle").
func checkUseStatement(line string, caps *capability.CapabilitySet, path string, lineNo int) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "use ") {
		return false
	}

	// Extract namespace: "use GuzzleHttp\Client;" → "GuzzleHttp\Client"
	ns := strings.TrimPrefix(trimmed, "use ")
	ns = strings.TrimSuffix(ns, ";")
	ns = strings.TrimSpace(ns)

	parts := strings.SplitN(ns, `\`, 3)
	if len(parts) < 2 {
		return false
	}
	vendor := strings.ToLower(parts[0])
	pkg := strings.ToLower(parts[1])

	// Try exact vendor/package match first.
	composerName := vendor + "/" + pkg
	if importCaps, ok := phpPatterns.Imports[composerName]; ok {
		addImportCaps(caps, importCaps, composerName, path, lineNo)
		return true
	}

	// Fallback: find any pattern that starts with "vendor/" and use it.
	prefix := vendor + "/"
	for patternName, importCaps := range phpPatterns.Imports {
		if strings.HasPrefix(patternName, prefix) {
			addImportCaps(caps, importCaps, patternName, path, lineNo)
			return true
		}
	}
	return false
}

func addImportCaps(caps *capability.CapabilitySet, importCaps []capability.Capability, name, path string, lineNo int) {
	for _, c := range importCaps {
		caps.AddWithEvidence(c, capability.CapabilityEvidence{
			File:       path,
			Line:       lineNo,
			Context:    "use " + name,
			Via:        "import",
			Confidence: 0.90,
		})
	}
}
