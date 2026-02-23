package cpp

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// cppPatterns holds the C/C++ PatternSet loaded from languages/cpp.yaml.
var cppPatterns = capability.MustLoadPatterns("cpp")

// cppExtensions is the set of C/C++ source and header file extensions.
var cppExtensions = map[string]bool{
	".c":   true,
	".cpp": true,
	".cc":  true,
	".cxx": true,
	".h":   true,
	".hpp": true,
}

// Detect walks C/C++ source files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if cppExtensions[strings.ToLower(filepath.Ext(path))] {
			scanCppFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanCppFile scans a single C/C++ source file for capability evidence.
func scanCppFile(path string, caps *capability.CapabilitySet) {
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

		// Match #include directives.
		if strings.HasPrefix(trimmed, "#include") {
			checkCppInclude(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range cppPatterns.CallSites {
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

// checkCppInclude detects capabilities from C/C++ #include directives.
// Handles both #include <path/to/header.h> and #include "path/to/header.h".
func checkCppInclude(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	// Strip "#include" prefix and surrounding whitespace.
	rest, ok := strings.CutPrefix(trimmed, "#include")
	if !ok {
		return
	}
	rest = strings.TrimSpace(rest)
	if len(rest) == 0 {
		return
	}

	// Extract the header path from angle brackets or quotes.
	var header string
	switch rest[0] {
	case '<':
		end := strings.Index(rest, ">")
		if end < 0 {
			return
		}
		header = rest[1:end]
	case '"':
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return
		}
		header = rest[1 : end+1]
	default:
		return
	}

	// Extract base name: strip directory prefix and extension.
	base := filepath.Base(header)
	// Remove extension (e.g., ".h", ".hpp").
	if idx := strings.LastIndex(base, "."); idx > 0 {
		base = base[:idx]
	}

	// Try multiple candidates: base name, then progressive path shortening with
	// slashes replaced by dashes.
	candidates := buildIncludeCandidates(header, base)

	for _, candidate := range candidates {
		if importCaps, ok := cppPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    strings.TrimSpace(line),
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}

// buildIncludeCandidates returns the set of lookup keys to try for an include path.
func buildIncludeCandidates(header, base string) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(s string) {
		s = strings.ToLower(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	add(base)
	add(header)
	// Strip extension from full path and try with dashes.
	noExt := header
	if idx := strings.LastIndex(header, "."); idx > 0 {
		noExt = header[:idx]
	}
	add(strings.ReplaceAll(noExt, "/", "-"))
	// Top-level directory only (e.g., "curl/curl.h" → "curl").
	if dir, _, ok := strings.Cut(header, "/"); ok {
		add(dir)
	}

	return out
}
