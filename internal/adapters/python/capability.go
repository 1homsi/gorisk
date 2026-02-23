package python

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// pythonPatterns holds the Python PatternSet loaded from languages/python.yaml.
var pythonPatterns = capability.MustLoadPatterns("python")

// Detect walks .py files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".py" {
			scanPyFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanPyFile scans a single Python source file for capability evidence.
func scanPyFile(path string, caps *capability.CapabilitySet) {
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

		// Match import statements: "import X" or "from X import Y".
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
			checkImport(line, caps, path, lineNo)
			continue
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range pythonPatterns.CallSites {
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

// checkImport detects capabilities from Python import statements.
// Handles both "import X" and "from X import Y" forms.
func checkImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	var moduleName string
	if rest, ok := strings.CutPrefix(trimmed, "from "); ok {
		// "from X.Y import Z" → module is "X.Y", top-level is "X"
		moduleName = strings.Fields(rest)[0]
	} else if rest, ok := strings.CutPrefix(trimmed, "import "); ok {
		// "import X, Y" → first module is "X"
		moduleName = strings.Fields(strings.SplitN(rest, ",", 2)[0])[0]
	}

	if moduleName == "" {
		return
	}

	// Try exact match first, then top-level module.
	addImportCaps(moduleName, line, caps, path, lineNo)

	// Also try the top-level module name (e.g. "os" from "os.path").
	topLevel := strings.SplitN(moduleName, ".", 2)[0]
	if topLevel != moduleName {
		addImportCaps(topLevel, line, caps, path, lineNo)
	}
}

func addImportCaps(moduleName string, line string, caps *capability.CapabilitySet, path string, lineNo int) {
	importCaps, ok := pythonPatterns.Imports[moduleName]
	if !ok {
		return
	}
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
