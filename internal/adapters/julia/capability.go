package julia

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// juliaPatterns holds the Julia PatternSet loaded from languages/julia.yaml.
var juliaPatterns = capability.MustLoadPatterns("julia")

// Detect walks .jl files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".jl" {
			scanJlFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanJlFile scans a single Julia source file for capability evidence.
func scanJlFile(path string, caps *capability.CapabilitySet) {
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

		// Detect `using X`, `using X: f, g`, or `import X`.
		if strings.HasPrefix(trimmed, "using ") || strings.HasPrefix(trimmed, "import ") {
			checkJuliaImport(trimmed, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range juliaPatterns.CallSites {
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

// checkJuliaImport detects capabilities from a `using X` or `import X` statement.
func checkJuliaImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	var rest string
	switch {
	case strings.HasPrefix(line, "using "):
		rest, _ = strings.CutPrefix(line, "using ")
	case strings.HasPrefix(line, "import "):
		rest, _ = strings.CutPrefix(line, "import ")
	default:
		return
	}

	rest = strings.TrimSpace(rest)
	// Strip inline comment.
	if idx := strings.Index(rest, "#"); idx >= 0 {
		rest = strings.TrimSpace(rest[:idx])
	}
	if rest == "" {
		return
	}

	// `using X: f, g` — strip the `: f, g` part.
	modulePart, _, _ := strings.Cut(rest, ":")
	modulePart = strings.TrimSpace(modulePart)

	// Handle `using X, Y, Z` — multiple modules.
	for _, mod := range strings.Split(modulePart, ",") {
		mod = strings.TrimSpace(mod)
		if mod == "" {
			continue
		}

		// Try exact name first, then top-level (before '.').
		candidates := []string{mod}
		if top, _, hasDot := strings.Cut(mod, "."); hasDot {
			candidates = append(candidates, top)
		}

		for _, candidate := range candidates {
			if importCaps, ok := juliaPatterns.Imports[candidate]; ok {
				for _, c := range importCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    line,
						Via:        "import",
						Confidence: 0.90,
					})
				}
				break
			}
		}
	}
}
