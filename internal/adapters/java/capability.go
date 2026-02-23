package java

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// javaPatterns holds the Java PatternSet loaded from languages/java.yaml.
var javaPatterns = capability.MustLoadPatterns("java")

// Detect walks .java files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".java" {
			scanJavaFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanJavaFile scans a single Java source file for capability evidence.
func scanJavaFile(path string, caps *capability.CapabilitySet) {
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

		// Match import statements: "import X.Y.Z;"
		if strings.HasPrefix(trimmed, "import ") {
			checkJavaImport(line, caps, path, lineNo)
			continue
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range javaPatterns.CallSites {
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

// checkJavaImport detects capabilities from Java import statements.
// Handles "import X.Y.Z;" and "import static X.Y.Z.method;".
func checkJavaImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	rest, ok := strings.CutPrefix(trimmed, "import ")
	if !ok {
		return
	}
	// Strip optional "static " keyword.
	rest, _ = strings.CutPrefix(rest, "static ")
	// Strip trailing semicolon and whitespace.
	moduleName := strings.TrimRight(strings.TrimSpace(rest), ";")
	if moduleName == "" {
		return
	}

	// Try progressively shorter prefixes: exact → up to each dot segment.
	parts := strings.Split(moduleName, ".")
	for i := len(parts); i >= 1; i-- {
		prefix := strings.Join(parts[:i], ".")
		if importCaps, ok := javaPatterns.Imports[prefix]; ok {
			for _, c := range importCaps {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    strings.TrimSpace(line),
					Via:        "import",
					Confidence: 0.90,
				})
			}
			// Use the most specific match only.
			return
		}
	}
}
