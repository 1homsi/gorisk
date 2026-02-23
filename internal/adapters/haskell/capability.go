package haskell

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// haskellPatterns holds the Haskell PatternSet loaded from languages/haskell.yaml.
var haskellPatterns = capability.MustLoadPatterns("haskell")

// Detect walks .hs and .lhs files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".hs" || ext == ".lhs" {
			scanHsFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanHsFile scans a single Haskell source file for capability evidence.
func scanHsFile(path string, caps *capability.CapabilitySet) {
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

		// Match import statements: "import X.Y.Z" or "import qualified X.Y.Z".
		if strings.HasPrefix(trimmed, "import ") {
			checkHaskellImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range haskellPatterns.CallSites {
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

// checkHaskellImport detects capabilities from Haskell import statements.
// Handles: import X.Y.Z, import qualified X.Y.Z, import X.Y.Z (...)
func checkHaskellImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	// Strip "import" prefix.
	rest, ok := strings.CutPrefix(trimmed, "import")
	if !ok {
		return
	}
	rest = strings.TrimSpace(rest)

	// Strip optional "qualified".
	rest, _ = strings.CutPrefix(rest, "qualified")
	rest = strings.TrimSpace(rest)

	// Module name ends at whitespace, '(', or end.
	module := rest
	for _, stop := range []string{" ", "\t", "(", " as "} {
		if idx := strings.Index(module, stop); idx >= 0 {
			module = module[:idx]
		}
	}
	module = strings.TrimSpace(module)

	if module == "" {
		return
	}

	// Build lookup candidates from the module name.
	candidates := buildModuleCandidates(module)

	for _, candidate := range candidates {
		if importCaps, ok := haskellPatterns.Imports[candidate]; ok {
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

// buildModuleCandidates generates lookup keys from a Haskell module path.
// Strategy: convert dots to dashes, try progressive shortening from the left.
// Example: "Network.HTTP.Client" → ["network-http-client", "network-http", "network",
//
//	"http-client", "http", "client"]
func buildModuleCandidates(module string) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(s string) {
		s = strings.ToLower(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	// Full module with dots → dashes.
	add(strings.ReplaceAll(module, ".", "-"))

	// Progressive shortening: drop leading components one at a time.
	parts := strings.Split(module, ".")
	for i := 0; i < len(parts); i++ {
		sub := strings.Join(parts[i:], "-")
		add(sub)
	}

	// Also try just the lowercase module as-is.
	add(module)

	return out
}
