package scala

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// ScalaFunction represents a Scala function found in source.
type ScalaFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// reScalaFunc matches Scala method/function declarations.
	reScalaFunc = regexp.MustCompile(`^\s*(?:override\s+|private\s+|protected\s+|final\s+)?def\s+(\w+)\s*[\(\[]`)

	// reScalaCall matches function/method calls: obj.method( or func(
	reScalaCall = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// scalaKeywords are identifiers to skip in call detection.
var scalaKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "match": true, "try": true,
	"catch": true, "new": true, "return": true, "class": true, "interface": true,
	"object": true, "import": true, "package": true, "throw": true,
	"finally": true, "else": true, "do": true, "break": true, "continue": true,
	"case": true, "def": true, "val": true, "var": true, "trait": true,
	"extends": true, "with": true, "type": true, "implicit": true,
	"override": true, "sealed": true, "abstract": true, "lazy": true,
	"yield": true, "forSome": true,
}

// DetectFunctions parses Scala source files and returns per-function capability
// sets and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, scalaFile := range files {
		fpath := filepath.Join(dir, scalaFile)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findScalaFunctions(string(data))

		for _, fn := range fileFuncs {
			sym := ir.Symbol{
				Package: dir,
				Name:    fn.Name,
				Kind:    "function",
			}

			fc := ir.FunctionCaps{
				Symbol:     sym,
				DirectCaps: capability.CapabilitySet{},
				Depth:      0,
			}

			detectScalaFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findScalaCalls(fn.Body)
			for _, calleeName := range calls {
				calleeSym := ir.Symbol{
					Package: dir,
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

// findScalaFunctions scans Scala source and extracts function boundaries.
func findScalaFunctions(source string) []ScalaFunction {
	var functions []ScalaFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reScalaFunc.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if scalaKeywords[name] {
			continue
		}

		// Expression body: def foo(...) = expr  (no braces)
		if strings.Contains(line, "=") && !strings.Contains(line, "{") {
			// Check if "=" appears after the closing paren/bracket of the parameter list.
			parenIdx := strings.Index(line, "(")
			eqIdx := strings.Index(line, "=")
			if parenIdx >= 0 && eqIdx > parenIdx {
				functions = append(functions, ScalaFunction{
					Name:      name,
					StartLine: i + 1,
					EndLine:   i + 1,
					Body:      line,
				})
				continue
			}
		}

		// Find the opening brace (may be on same or next non-blank line).
		braceIdx := i
		if !strings.Contains(line, "{") {
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
				// Abstract definition with no body.
				continue
			}
		}

		endLine := findScalaBraceEnd(lines, braceIdx)
		body := strings.Join(lines[i:endLine+1], "\n")

		functions = append(functions, ScalaFunction{
			Name:      name,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      body,
		})
	}

	return functions
}

// findScalaBraceEnd finds the closing brace of a Scala block.
func findScalaBraceEnd(lines []string, startIdx int) int {
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

// detectScalaFunctionCaps scans a function body for capability-indicating patterns.
func detectScalaFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range scalaPatterns.CallSites {
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

// findScalaCalls extracts called function/method names from a function body.
func findScalaCalls(body string) []string {
	var calls []string
	seen := make(map[string]bool)

	matches := reScalaCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var name string
		if m[2] != "" {
			name = m[2]
		} else {
			name = m[1]
		}
		if !scalaKeywords[name] && !seen[name] && name != "" {
			calls = append(calls, name)
			seen[name] = true
		}
	}
	return calls
}
