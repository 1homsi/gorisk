package python

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// pyFunc represents a Python function found in source.
type pyFunc struct {
	Name      string
	StartLine int
	Body      string
}

var (
	// def name( or def name\n
	rePyFuncDef = regexp.MustCompile(`(?m)^(\s*)def\s+(\w+)\s*\(`)

	// async def name(
	rePyAsyncDef = regexp.MustCompile(`(?m)^(\s*)async\s+def\s+(\w+)\s*\(`)

	// bare function call: name(
	rePyCall = regexp.MustCompile(`\b(\w+)\s*\(`)
)

// DetectFunctions parses Python files and returns per-function capability sets
// and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, f := range files {
		fpath := filepath.Join(dir, f)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findPyFunctions(string(data))

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

			detectPyFunctionCapabilities(&fc, fn.Body, fpath, fn.StartLine)

			// Build call edges from function body.
			for _, callee := range findPyCalls(fn.Body) {
				edges = append(edges, ir.CallEdge{
					Caller: sym,
					Callee: ir.Symbol{
						Package: dir,
						Name:    callee,
						Kind:    "function",
					},
				})
			}

			funcs[sym.String()] = fc
		}
	}

	return funcs, edges, nil
}

// findPyFunctions extracts function definitions from Python source.
// It uses indentation to determine the end of each function body.
func findPyFunctions(source string) []pyFunc {
	var result []pyFunc
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		var m []string

		if m = rePyFuncDef.FindStringSubmatch(line); m == nil {
			m = rePyAsyncDef.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}

		indent := len(m[1]) // number of leading spaces for the def line
		name := m[2]
		startLine := i + 1

		// Collect body: lines after the def until we return to or below def indent.
		var bodyLines []string
		bodyLines = append(bodyLines, line)
		j := i + 1
		for j < len(lines) {
			l := lines[j]
			// Blank lines are always part of the body.
			if strings.TrimSpace(l) == "" {
				bodyLines = append(bodyLines, l)
				j++
				continue
			}
			lineIndent := countLeadingSpaces(l)
			if lineIndent <= indent {
				break
			}
			bodyLines = append(bodyLines, l)
			j++
		}

		result = append(result, pyFunc{
			Name:      name,
			StartLine: startLine,
			Body:      strings.Join(bodyLines, "\n"),
		})
	}

	return result
}

// countLeadingSpaces returns the number of leading space characters (treating
// a tab as one space for simplicity).
func countLeadingSpaces(s string) int {
	n := 0
	for _, ch := range s {
		if ch == ' ' || ch == '\t' {
			n++
		} else {
			break
		}
	}
	return n
}

// detectPyFunctionCapabilities scans function body lines for call-site patterns.
func detectPyFunctionCapabilities(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lineNo := startLine + i
		for pattern, caps := range pythonPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range caps {
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

// findPyCalls returns unique function names called in the body.
func findPyCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	matches := rePyCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		name := m[1]
		if isPyKeyword(name) || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
	}
	return calls
}

// isPyKeyword filters Python keywords and common built-ins from call names.
func isPyKeyword(name string) bool {
	skip := map[string]bool{
		"if": true, "else": true, "elif": true, "for": true, "while": true,
		"with": true, "return": true, "yield": true, "raise": true,
		"import": true, "from": true, "as": true, "in": true, "not": true,
		"and": true, "or": true, "is": true, "lambda": true, "class": true,
		"def": true, "del": true, "pass": true, "break": true, "continue": true,
		"try": true, "except": true, "finally": true, "assert": true,
		"print": true, "len": true, "range": true, "str": true, "int": true,
		"list": true, "dict": true, "set": true, "tuple": true, "bool": true,
		"type": true, "super": true, "self": true, "cls": true,
		"True": true, "False": true, "None": true,
	}
	return skip[name]
}
