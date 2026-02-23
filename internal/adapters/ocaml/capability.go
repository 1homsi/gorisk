package ocaml

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// ocamlPatterns holds the OCaml PatternSet loaded from languages/ocaml.yaml.
var ocamlPatterns = capability.MustLoadPatterns("ocaml")

// Detect walks .ml and .mli files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".ml" || ext == ".mli" {
			scanMlFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanMlFile scans a single OCaml source file for capability evidence.
func scanMlFile(path string, caps *capability.CapabilitySet) {
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

		// Detect `open X` or `open X.Y` — extract top-level module name.
		if strings.HasPrefix(trimmed, "open ") {
			checkOCamlOpen(trimmed, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range ocamlPatterns.CallSites {
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

// checkOCamlOpen detects capabilities from an `open X` or `open X.Y` statement.
// The top-level module name is lowercased for lookup in ocamlPatterns.Imports.
func checkOCamlOpen(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	rest, ok := strings.CutPrefix(line, "open ")
	if !ok {
		return
	}
	rest = strings.TrimSpace(rest)
	// Strip trailing comment (* ... *) if present.
	if idx := strings.Index(rest, "(*"); idx >= 0 {
		rest = strings.TrimSpace(rest[:idx])
	}
	if rest == "" {
		return
	}

	// Take the top-level module name (before any '.' qualifier).
	topModule, _, _ := strings.Cut(rest, ".")
	topModule = strings.TrimSpace(topModule)
	if topModule == "" {
		return
	}

	// Lowercase for lookup: `Unix` → "unix", `Cohttp` → "cohttp".
	key := strings.ToLower(topModule)

	if importCaps, ok := ocamlPatterns.Imports[key]; ok {
		for _, c := range importCaps {
			caps.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       path,
				Line:       lineNo,
				Context:    line,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}
