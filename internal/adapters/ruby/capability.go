package ruby

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// rubyPatterns holds the Ruby PatternSet loaded from languages/ruby.yaml.
var rubyPatterns = capability.MustLoadPatterns("ruby")

// Detect walks .rb files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".rb" {
			scanRbFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanRbFile scans a single Ruby source file for capability evidence.
func scanRbFile(path string, caps *capability.CapabilitySet) {
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

		// Match require/require_relative/load statements.
		if strings.HasPrefix(trimmed, "require ") ||
			strings.HasPrefix(trimmed, "require_relative ") ||
			strings.HasPrefix(trimmed, "require(") ||
			strings.HasPrefix(trimmed, "load ") {
			checkRubyImport(line, caps, path, lineNo)
			// Don't skip call_site scan; "require " is also a call_site pattern.
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range rubyPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    strings.TrimSpace(line),
						Via:        "callSite",
						Confidence: 0.60,
					})
				}
			}
		}
	}
}

// checkRubyImport detects capabilities from Ruby require/load statements.
func checkRubyImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	var libName string
	for _, prefix := range []string{"require_relative ", "require ", "load "} {
		if rest, ok := strings.CutPrefix(trimmed, prefix); ok {
			// Strip quotes, parentheses, and any trailing comment.
			rest = strings.TrimLeft(rest, `("'`)
			// Take up to first closing quote/paren/space.
			for _, stop := range []string{`"`, `'`, `)`, ` `, `\t`, `#`} {
				if idx := strings.Index(rest, stop); idx >= 0 {
					rest = rest[:idx]
				}
			}
			libName = strings.TrimSuffix(rest, ".rb")
			break
		}
	}

	if libName == "" {
		return
	}

	// Normalise: "net/http" → try "net-http" and "net/http".
	candidates := []string{
		libName,
		strings.ReplaceAll(libName, "/", "-"),
		strings.ReplaceAll(libName, "_", "-"),
	}

	for _, candidate := range candidates {
		if importCaps, ok := rubyPatterns.Imports[candidate]; ok {
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
