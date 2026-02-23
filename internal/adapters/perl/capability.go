package perl

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// perlPatterns holds the Perl PatternSet loaded from languages/perl.yaml.
var perlPatterns = capability.MustLoadPatterns("perl")

// reUseImport matches "use Module::Name" or "use Module::Name qw(...)".
var reUseImport = regexp.MustCompile(`^use\s+([A-Za-z][A-Za-z0-9:_]*)`)

// Detect walks .pl, .pm, and .t files in dir and returns the combined
// capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".pl" || ext == ".pm" || ext == ".t" {
			scanPerlFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanPerlFile scans a single Perl source file for capability evidence.
func scanPerlFile(path string, caps *capability.CapabilitySet) {
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
		trimmed := strings.TrimSpace(line)

		// 1. Detect "use Module::Name" — confidence 0.90.
		if m := reUseImport.FindStringSubmatch(trimmed); len(m) >= 2 {
			modName := m[1]
			if importCaps, ok := perlPatterns.Imports[modName]; ok {
				for _, c := range importCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    trimmed,
						Via:        "import",
						Confidence: 0.90,
					})
				}
			}
		}

		// 2. Call-site substring patterns — confidence 0.75.
		for pattern, patCaps := range perlPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    trimmed,
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}
