package dart

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// dartFunction represents a Dart function found in source.
type dartFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// Matches Dart function/method declarations that end with an opening brace:
	//   void foo() {
	//   Future<String> loadData(String id) async {
	//   static int compute(int x) {
	reFuncDecl = regexp.MustCompile(`^\s*(?:\w+\s+)+(\w+)\s*\([^;]*\)\s*(?:async\s*)?\{`)

	// Direct call: foo(  or  obj.method(
	reCallSite = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// skipDartKeywords lists identifiers that are not real function calls.
var skipDartKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true,
	"return": true, "new": true, "class": true, "interface": true,
	"import": true, "package": true, "var": true, "final": true,
	"const": true, "assert": true, "throw": true, "rethrow": true,
}

// DetectFunctions parses Dart source files and returns per-function
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

		fileFuncs := findDartFunctions(string(data))

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

			detectDartFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findDartCalls(fn.Body)
			for _, calleeName := range calls {
				calleeSym := ir.Symbol{
					Package: pkgName,
					Name:    calleeName,
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

// findDartFunctions scans Dart source code and extracts function boundaries.
func findDartFunctions(source string) []dartFunction {
	var functions []dartFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reFuncDecl.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		funcName := m[1]
		// Skip common control-flow keywords that can appear before '('
		if skipDartKeywords[funcName] {
			continue
		}
		endLine := findDartBraceBodyEnd(lines, i)
		body := strings.Join(lines[i:endLine+1], "\n")
		functions = append(functions, dartFunction{
			Name:      funcName,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      body,
		})
	}

	return functions
}

// findDartBraceBodyEnd finds the closing brace of a brace-delimited body.
func findDartBraceBodyEnd(lines []string, startIdx int) int {
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

// detectDartFunctionCaps scans a function body for capability evidence using
// the dartPatterns call-site map.
func detectDartFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range dartPatterns.CallSites {
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

// findDartCalls extracts called function/method names from a function body.
func findDartCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	matches := reCallSite.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var name string
		if m[2] != "" {
			name = m[2]
		} else {
			name = m[1]
		}
		if name != "" && !skipDartKeywords[name] && !seen[name] {
			calls = append(calls, name)
			seen[name] = true
		}
	}
	return calls
}
