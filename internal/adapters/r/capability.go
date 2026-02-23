package r

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// rPatterns holds the R PatternSet loaded from languages/r.yaml.
var rPatterns = capability.MustLoadPatterns("r")

// reLibrary matches library(PkgName) or require(PkgName) calls.
// It captures the package name inside the parentheses.
var reLibrary = regexp.MustCompile(`(?:library|require)\s*\(\s*["']?([A-Za-z][A-Za-z0-9._]*)["']?\s*\)`)

// reNamespace matches Package::Function( — captures the package name.
var reNamespace = regexp.MustCompile(`([A-Za-z][A-Za-z0-9._]*)::`)

// Detect walks .R and .r files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".r" {
			scanRFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanRFile scans a single R source file for capability evidence.
func scanRFile(path string, caps *capability.CapabilitySet) {
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

		// 1. Detect library(X) / require(X) — confidence 0.90.
		if matches := reLibrary.FindAllStringSubmatch(line, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) < 2 {
					continue
				}
				pkgName := m[1]
				if importCaps, ok := rPatterns.Imports[pkgName]; ok {
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

		// 2. Detect X::Y( namespace-qualified calls — confidence 0.85.
		if nsMatches := reNamespace.FindAllStringSubmatch(line, -1); len(nsMatches) > 0 {
			for _, m := range nsMatches {
				if len(m) < 2 {
					continue
				}
				pkgName := m[1]
				if importCaps, ok := rPatterns.Imports[pkgName]; ok {
					for _, c := range importCaps {
						caps.AddWithEvidence(c, capability.CapabilityEvidence{
							File:       path,
							Line:       lineNo,
							Context:    strings.TrimSpace(line),
							Via:        "import",
							Confidence: 0.85,
						})
					}
				}
			}
		}

		// 3. Call-site substring patterns — confidence 0.75.
		for pattern, patCaps := range rPatterns.CallSites {
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
