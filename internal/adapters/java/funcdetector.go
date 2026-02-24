package java

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// JavaFunction represents a Java method found in source.
type JavaFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// reJavaMethod matches Java method declarations.
	// Captures the method name (last word before the opening parenthesis).
	reJavaMethod = regexp.MustCompile(`^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|override)\s+)*(?:\w+(?:<[^>]*>)?(?:\[\])*)\s+(\w+)\s*\(`)

	// reJavaCall matches method/function calls: obj.method( or func(
	reJavaCall = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// javaKeywords are identifiers that look like method names but are keywords.
var javaKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "try": true,
	"catch": true, "synchronized": true, "new": true, "return": true,
	"class": true, "interface": true, "object": true, "import": true,
	"package": true, "throw": true, "throws": true, "finally": true,
	"else": true, "do": true, "case": true, "default": true,
	"instanceof": true, "assert": true, "break": true, "continue": true,
}

// DetectFunctions parses Java source files and returns per-function capability
// sets and call edges.
func DetectFunctions(dir, pkgName string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, javaFile := range files {
		fpath := filepath.Join(dir, javaFile)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findJavaFunctions(string(data))

		for _, fn := range fileFuncs {
			sym := ir.Symbol{
				Package: pkgName,
				Name:    fn.Name,
				Kind:    "function",
			}

			fc := ir.FunctionCaps{
				Symbol:     sym,
				DirectCaps: capability.CapabilitySet{},
				Depth:      0,
			}

			detectJavaFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findJavaCalls(fn.Body)
			for _, calleeName := range calls {
				calleeSym := ir.Symbol{
					Package: pkgName,
					Name:    calleeName,
					Kind:    "function",
				}
				edges = append(edges, ir.CallEdge{Caller: sym, Callee: calleeSym})
			}

			funcs[sym.String()] = fc
		}
	}

	return funcs, edges, nil
}

// findJavaFunctions scans Java source and extracts method boundaries.
func findJavaFunctions(source string) []JavaFunction {
	var functions []JavaFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reJavaMethod.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if javaKeywords[name] {
			continue
		}

		// The method declaration must be followed by a '{' (on the same or next
		// non-empty line) to be a concrete method (not abstract / interface).
		braceIdx := i
		if !strings.Contains(line, "{") {
			// Look ahead for the opening brace.
			found := false
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if strings.Contains(lines[j], "{") {
					braceIdx = j
					found = true
					break
				}
				if strings.TrimSpace(lines[j]) != "" {
					break
				}
			}
			if !found {
				continue
			}
		}

		endLine := findBraceEnd(lines, braceIdx)
		body := strings.Join(lines[i:endLine+1], "\n")

		functions = append(functions, JavaFunction{
			Name:      name,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      body,
		})
	}

	return functions
}

// findBraceEnd finds the closing brace of a block using brace counting.
func findBraceEnd(lines []string, startIdx int) int {
	depth := 0
	started := false
	for i := startIdx; i < len(lines); i++ {
		for _, ch := range lines[i] {
			if ch == '{' {
				depth++
				started = true
			}
			if ch == '}' {
				depth--
				if started && depth == 0 {
					return i
				}
			}
		}
	}
	if startIdx+100 < len(lines) {
		return startIdx + 100
	}
	return len(lines) - 1
}

// detectJavaFunctionCaps scans a function body for capability-indicating patterns.
func detectJavaFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range javaPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					fc.DirectCaps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       fpath,
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

// findJavaCalls extracts called function/method names from a function body.
func findJavaCalls(body string) []string {
	var calls []string
	seen := make(map[string]bool)

	matches := reJavaCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var name string
		if m[2] != "" {
			name = m[2]
		} else {
			name = m[1]
		}
		if !javaKeywords[name] && !seen[name] && name != "" {
			calls = append(calls, name)
			seen[name] = true
		}
	}
	return calls
}
