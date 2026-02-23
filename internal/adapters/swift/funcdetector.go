package swift

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// swiftFunction represents a Swift function found in source.
type swiftFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// Matches Swift function declarations:
	//   func foo(...)
	//   public func foo<T>(...)
	//   static async func foo(...)
	reFuncDecl = regexp.MustCompile(`^\s*(?:\w+\s+)*func\s+(\w+)\s*[<(]`)

	// Direct call: foo(  or  obj.method(
	reCallSite = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// skipSwiftKeywords lists identifiers that are not real function calls.
var skipSwiftKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true,
	"guard": true, "defer": true, "return": true, "throw": true,
	"new": true, "class": true, "struct": true, "enum": true,
	"interface": true, "import": true, "package": true, "func": true,
	"var": true, "let": true, "where": true,
}

// DetectFunctions parses Swift source files and returns per-function
// capability sets and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, file := range files {
		fpath := filepath.Join(dir, file)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findSwiftFunctions(string(data))

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

			detectSwiftFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findSwiftCalls(fn.Body)
			for _, calleeName := range calls {
				calleeSym := ir.Symbol{
					Package: dir,
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

// findSwiftFunctions scans Swift source code and extracts function boundaries.
func findSwiftFunctions(source string) []swiftFunction {
	var functions []swiftFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reFuncDecl.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		funcName := m[1]
		endLine := findBraceBodyEnd(lines, i)
		body := strings.Join(lines[i:endLine+1], "\n")
		functions = append(functions, swiftFunction{
			Name:      funcName,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      body,
		})
	}

	return functions
}

// findBraceBodyEnd finds the closing brace of a brace-delimited body starting
// at startIdx by counting { and } characters.
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

// detectSwiftFunctionCaps scans a function body for capability evidence using
// the swiftPatterns call-site map.
func detectSwiftFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range swiftPatterns.CallSites {
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

// findSwiftCalls extracts called function/method names from a function body.
func findSwiftCalls(body string) []string {
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
		if name != "" && !skipSwiftKeywords[name] && !seen[name] {
			calls = append(calls, name)
			seen[name] = true
		}
	}
	return calls
}
