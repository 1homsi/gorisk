package kotlin

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// kotlinPatterns holds the Kotlin PatternSet loaded from languages/kotlin.yaml.
var kotlinPatterns = capability.MustLoadPatterns("kotlin")

// Detect walks .kt and .kts files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".kt" || ext == ".kts" {
			scanKtFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanKtFile scans a single Kotlin source file for capability evidence.
func scanKtFile(path string, caps *capability.CapabilitySet) {
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

		// Match import statements.
		if strings.HasPrefix(trimmed, "import ") {
			checkKotlinImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range kotlinPatterns.CallSites {
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

// checkKotlinImport detects capabilities from a Kotlin import statement by
// performing a longest-prefix lookup against the kotlin.yaml imports map.
// The imports map is keyed by "group:artifact", e.g. "io.ktor:ktor-client-core".
// We try to convert the import path "io.ktor.client.HttpClient" → "io.ktor" and
// match against known group:artifact prefixes.
func checkKotlinImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(trimmed, "import ")
	if !ok {
		return
	}
	rest = strings.TrimSpace(rest)

	// Try longest-prefix match against each known import key.
	// Import keys are in "group:artifact" form like "io.ktor:ktor-client-core".
	// Convert to dotted prefix: "io.ktor.ktor-client-core" and "io.ktor".
	bestLen := 0
	var bestCaps []capability.Capability

	for key, importCaps := range kotlinPatterns.Imports {
		// Build dotted prefix from "group:artifact".
		group, artifact, hasSep := strings.Cut(key, ":")
		var prefix string
		if hasSep {
			// Convert artifact hyphens to dots for matching (Kotlin package convention).
			artifactDot := strings.ReplaceAll(artifact, "-", ".")
			prefix = group + "." + artifactDot
		} else {
			prefix = strings.ReplaceAll(key, "-", ".")
		}

		if strings.HasPrefix(rest, prefix) && len(prefix) > bestLen {
			bestLen = len(prefix)
			bestCaps = importCaps
		}

		// Also try matching on just the group prefix (e.g. "io.ktor").
		if hasSep && strings.HasPrefix(rest, group+".") && len(group)+1 > bestLen {
			// Only use group-only match if no artifact-level match was found yet.
			if bestLen == 0 {
				bestLen = len(group) + 1
				bestCaps = importCaps
			}
		}
	}

	for _, c := range bestCaps {
		caps.AddWithEvidence(c, capability.CapabilityEvidence{
			File:       path,
			Line:       lineNo,
			Context:    strings.TrimSpace(line),
			Via:        "import",
			Confidence: 0.90,
		})
	}
}
