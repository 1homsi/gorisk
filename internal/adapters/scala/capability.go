package scala

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// scalaPatterns holds the Scala PatternSet loaded from languages/scala.yaml.
var scalaPatterns = capability.MustLoadPatterns("scala")

// Detect walks .scala files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".scala" {
			scanScalaFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanScalaFile scans a single Scala source file for capability evidence.
func scanScalaFile(path string, caps *capability.CapabilitySet) {
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
			checkScalaImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range scalaPatterns.CallSites {
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

// checkScalaImport detects capabilities from a Scala import statement by
// performing a longest-prefix lookup against the scala.yaml imports map.
// Handles wildcard imports: `import org.http4s._` — the `._` suffix is stripped.
func checkScalaImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(trimmed, "import ")
	if !ok {
		return
	}
	rest = strings.TrimSpace(rest)

	// Strip Scala wildcard suffix `._`
	rest = strings.TrimSuffix(rest, "._")

	bestLen := 0
	var bestCaps []capability.Capability

	for key, importCaps := range scalaPatterns.Imports {
		// Import keys are "org:name" (sbt format).
		// Convert to dotted prefix: "org.name" for Scala import matching.
		org, name, hasSep := strings.Cut(key, ":")
		var prefix string
		if hasSep {
			// Scala package names typically use dots and no hyphens, but library
			// artifact names may contain hyphens. Try both with and without hyphen.
			nameDot := strings.ReplaceAll(name, "-", ".")
			prefix = org + "." + nameDot
		} else {
			prefix = strings.ReplaceAll(key, "-", ".")
		}

		if strings.HasPrefix(rest, prefix) && len(prefix) > bestLen {
			bestLen = len(prefix)
			bestCaps = importCaps
		}

		// Also try group-only prefix match.
		if hasSep && strings.HasPrefix(rest, org+".") && len(org)+1 > bestLen {
			if bestLen == 0 {
				bestLen = len(org) + 1
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
