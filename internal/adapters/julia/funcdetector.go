package julia

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// reFuncMultiLine matches Julia multi-line function definitions:
//
//	function name(...) ... end
var reFuncMultiLine = regexp.MustCompile(`^\s*function\s+(\w+)\s*(?:\{[^}]*\})?\s*\(`)

// reFuncSingleLine matches Julia single-line function definitions:
//
//	name(args) = expr
var reFuncSingleLine = regexp.MustCompile(`^\s*(\w+)\s*(?:\{[^}]*\})?\s*\([^)]*\)\s*=\s*[^=]`)

// reJuliaCall matches function calls: identifier( and obj.method(
var reJuliaCall = regexp.MustCompile(`\b(\w+)\s*\(`)

// reJuliaMethodCall matches qualified calls: obj.method(
var reJuliaMethodCall = regexp.MustCompile(`(\w+)\.(\w+)\s*\(`)

// juliaCallKeywords are Julia keywords that look like calls.
var juliaCallKeywords = map[string]bool{
	"if": true, "elseif": true, "while": true, "for": true, "function": true,
	"macro": true, "struct": true, "mutable": true, "abstract": true,
	"begin": true, "let": true, "try": true, "catch": true, "finally": true,
	"return": true, "end": true, "module": true, "baremodule": true,
	"do": true, "quote": true,
}

// JuliaFunction represents a Julia function found in source.
type JuliaFunction struct {
	Name       string
	StartLine  int
	EndLine    int
	Body       string
	SingleLine bool
}

// DetectFunctions parses Julia source files in dir and returns per-function
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

		fileFuncs := findJuliaFunctions(string(data))

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

			detectJuliaFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findJuliaCalls(fn.Body)
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

// findJuliaFunctions scans Julia source and extracts function boundaries.
func findJuliaFunctions(source string) []JuliaFunction {
	var functions []JuliaFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and blank lines.
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// Multi-line function definition.
		if m := reFuncMultiLine.FindStringSubmatch(line); m != nil {
			funcName := m[1]
			endLine := findJuliaEnd(lines, i)
			var bodyLines []string
			if endLine < len(lines) {
				bodyLines = lines[i : endLine+1]
			} else {
				bodyLines = lines[i:]
			}
			functions = append(functions, JuliaFunction{
				Name:      funcName,
				StartLine: i + 1,
				EndLine:   endLine + 1,
				Body:      strings.Join(bodyLines, "\n"),
			})
			continue
		}

		// Single-line function definition: name(args) = expr
		if m := reFuncSingleLine.FindStringSubmatch(line); m != nil {
			funcName := m[1]
			if juliaCallKeywords[funcName] {
				continue
			}
			functions = append(functions, JuliaFunction{
				Name:       funcName,
				StartLine:  i + 1,
				EndLine:    i + 1,
				Body:       line,
				SingleLine: true,
			})
		}
	}

	return functions
}

// findJuliaEnd finds the matching `end` for a Julia block starting at startIdx.
// It counts nested block-opening keywords vs `end` tokens.
func findJuliaEnd(lines []string, startIdx int) int {
	depth := 0
	openKws := []string{"function ", "if ", "for ", "while ", "let ", "try "}
	for i := startIdx; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		for _, kw := range openKws {
			if strings.HasPrefix(trimmed, kw) {
				depth++
			}
		}
		if trimmed == "end" || trimmed == "end;" {
			if depth <= 1 {
				return i
			}
			depth--
		}
	}
	end := startIdx + 100
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return end
}

// detectJuliaFunctionCaps scans a function body and records capability evidence.
func detectJuliaFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range juliaPatterns.CallSites {
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

// findJuliaCalls extracts unique callee names from a function body.
func findJuliaCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	// Qualified calls: obj.method(
	for _, m := range reJuliaMethodCall.FindAllStringSubmatch(body, -1) {
		name := m[2]
		if !juliaCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Direct calls: name(
	for _, m := range reJuliaCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if !juliaCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	return calls
}
