package r

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// reFuncAssign matches: name <- function( or name = function(
var reFuncAssign = regexp.MustCompile(`^\s*(\w+)\s*(?:<-|=)\s*function\s*\(`)

// reRCall matches direct function calls: identifier(
var reRCall = regexp.MustCompile(`\b(\w+)\s*\(`)

// reRNamespaceCall matches namespace-qualified calls: pkg::func(
var reRNamespaceCall = regexp.MustCompile(`(\w+)::(\w+)\s*\(`)

// rCallKeywords are R keywords/builtins that look like calls.
var rCallKeywords = map[string]bool{
	"if": true, "else": true, "while": true, "for": true, "repeat": true,
	"function": true, "return": true, "next": true, "break": true,
	"in": true, "TRUE": true, "FALSE": true, "NULL": true,
	"Inf": true, "NaN": true, "NA": true,
}

// RFunction represents an R function found in source.
type RFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

// DetectFunctions parses R source files in dir and returns per-function
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

		fileFuncs := findRFunctions(string(data))

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

			detectRFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findRCalls(fn.Body)
			for _, callee := range calls {
				calleeSym := ir.Symbol{
					Package: dir,
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

// findRFunctions scans R source and extracts function boundaries.
func findRFunctions(source string) []RFunction {
	var functions []RFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and blank lines.
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		m := reFuncAssign.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		funcName := m[1]
		endLine := findRBraceBodyEnd(lines, i)
		var bodyLines []string
		if endLine < len(lines) {
			bodyLines = lines[i : endLine+1]
		} else {
			bodyLines = lines[i:]
		}

		functions = append(functions, RFunction{
			Name:      funcName,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      strings.Join(bodyLines, "\n"),
		})
	}

	return functions
}

// findRBraceBodyEnd finds the closing brace of an R function body.
func findRBraceBodyEnd(lines []string, startIdx int) int {
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

// detectRFunctionCaps scans a function body and records capability evidence.
func detectRFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range rPatterns.CallSites {
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

// findRCalls extracts unique callee names from an R function body.
func findRCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	// Namespace-qualified calls: pkg::func(
	for _, m := range reRNamespaceCall.FindAllStringSubmatch(body, -1) {
		name := m[2]
		if !rCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Direct calls: name(
	for _, m := range reRCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if !rCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	return calls
}
