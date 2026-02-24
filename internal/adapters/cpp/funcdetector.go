package cpp

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// cppFunctionDef matches C/C++ function definition lines.
// Captures the function name. Excludes preprocessor, comments, and keywords.
var reCppFuncDef = regexp.MustCompile(`^\s*(?:[\w\*&:<>]+\s+)+(\w+)\s*\([^;]+\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{?\s*$`)

// reCppCall matches direct function calls: identifier(
var reCppCall = regexp.MustCompile(`\b(\w+)\s*\(`)

// reCppMethodCall matches method/namespace calls: obj.method( or Ns::func(
var reCppMethodCall = regexp.MustCompile(`(?:(\w+)::(\w+)|(\w+)\.(\w+))\s*\(`)

// cppCallKeywords lists C/C++ keywords that look like function calls but are not.
var cppCallKeywords = map[string]bool{
	"if": true, "while": true, "for": true, "switch": true, "catch": true,
	"return": true, "new": true, "delete": true, "sizeof": true,
	"alignof": true, "decltype": true, "throw": true,
}

// cppFuncDefKeywords lists keywords that can appear where a function definition
// regex would otherwise match.
var cppFuncDefKeywords = map[string]bool{
	"if": true, "while": true, "for": true, "switch": true, "catch": true,
	"else": true, "do": true, "try": true, "namespace": true,
	"class": true, "struct": true, "enum": true, "union": true,
}

// CppFunction represents a C/C++ function found in source.
type CppFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

// DetectFunctions parses C/C++ source files in dir and returns per-function
// capability sets and call edges.
func DetectFunctions(dir, pkgName string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, file := range files {
		fpath := filepath.Join(dir, file)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findCppFunctions(string(data))

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

			detectCppFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			// Build call edges from function body.
			calls := findCppCalls(fn.Body)
			for _, callee := range calls {
				calleeSym := ir.Symbol{
					Package: pkgName,
					Name:    callee,
					Kind:    "function",
				}
				edges = append(edges, ir.CallEdge{
					Caller: sym,
					Callee: calleeSym,
				})
			}

			funcs[sym.String()] = fc
		}
	}

	return funcs, edges, nil
}

// findCppFunctions scans C/C++ source code and extracts function boundaries.
func findCppFunctions(source string) []CppFunction {
	var functions []CppFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip preprocessor lines, line comments, and blank lines.
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") ||
			trimmed == "" {
			continue
		}

		m := reCppFuncDef.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		funcName := m[1]

		// Skip C/C++ keywords that match the regex.
		if cppFuncDefKeywords[funcName] {
			continue
		}

		// Skip common type/macro names that are not real functions.
		if strings.ToUpper(funcName) == funcName && len(funcName) > 2 {
			// All-caps identifiers are likely macros — skip.
			continue
		}

		endLine := findBraceBodyEnd(lines, i)
		var bodyLines []string
		if endLine < len(lines) {
			bodyLines = lines[i : endLine+1]
		} else {
			bodyLines = lines[i:]
		}

		functions = append(functions, CppFunction{
			Name:      funcName,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      strings.Join(bodyLines, "\n"),
		})
	}

	return functions
}

// findBraceBodyEnd finds the closing brace of a brace-delimited body starting
// at startIdx (inclusive), returning the line index of the closing brace.
func findBraceBodyEnd(lines []string, startIdx int) int {
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
	end := startIdx + 100
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return end
}

// detectCppFunctionCaps scans a function body and records capability evidence.
func detectCppFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range cppPatterns.CallSites {
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

// findCppCalls extracts unique callee names from a function body.
func findCppCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	// Method/namespace calls take priority.
	for _, m := range reCppMethodCall.FindAllStringSubmatch(body, -1) {
		var name string
		if m[2] != "" {
			name = m[2] // Ns::func
		} else if m[4] != "" {
			name = m[4] // obj.method
		}
		if name != "" && !cppCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Direct calls.
	for _, m := range reCppCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if !cppCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	return calls
}
