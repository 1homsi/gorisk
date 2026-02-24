package perl

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// rePerlSubDef matches Perl subroutine definitions:
//
//	sub name {         (body opens on same line)
//	sub name (proto) { (with prototype)
var rePerlSubDef = regexp.MustCompile(`^\s*sub\s+(\w+)\s*(?:\([^)]*\)\s*)?\{`)

// rePerlSubNoBody matches Perl subs whose body opens on the next line:
//
//	sub name
//	sub name (proto)
var rePerlSubNoBody = regexp.MustCompile(`^\s*sub\s+(\w+)\s*(?:\([^)]*\)\s*)?$`)

// rePerlCall matches direct Perl function calls: name(
var rePerlCall = regexp.MustCompile(`\b(\w+)\s*\(`)

// rePerlRefCall matches Perl function-reference calls: &name(
var rePerlRefCall = regexp.MustCompile(`&(\w+)\s*\(`)

// perlCallKeywords are Perl keywords/builtins excluded from call edges.
var perlCallKeywords = map[string]bool{
	"if": true, "elsif": true, "else": true, "unless": true,
	"while": true, "until": true, "for": true, "foreach": true,
	"sub": true, "return": true, "my": true, "our": true, "local": true,
	"use": true, "require": true, "package": true, "do": true,
	"print": true, "say": true, "die": true, "warn": true,
	"push": true, "pop": true, "shift": true, "unshift": true,
	"splice": true, "keys": true, "values": true, "each": true,
	"defined": true, "undef": true, "ref": true, "scalar": true,
	"chomp": true, "chop": true, "length": true, "substr": true,
}

// PerlFunction represents a Perl subroutine found in source.
type PerlFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

// DetectFunctions parses Perl source files in dir and returns per-function
// capability sets and call edges. pkgName is used as the Symbol.Package value.
func DetectFunctions(dir, pkgName string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, file := range files {
		fpath := filepath.Join(dir, file)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findPerlFunctions(string(data))

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

			detectPerlFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findPerlCalls(fn.Body)
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

// findPerlFunctions scans Perl source and extracts subroutine boundaries.
func findPerlFunctions(source string) []PerlFunction {
	var functions []PerlFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and blank lines.
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		var funcName string
		bodyStart := i

		if m := rePerlSubDef.FindStringSubmatch(line); m != nil {
			// Body opens on same line as sub declaration.
			funcName = m[1]
		} else if m := rePerlSubNoBody.FindStringSubmatch(line); m != nil {
			// Body may open on the next line.
			funcName = m[1]
			// Look ahead for the opening brace.
			if i+1 < len(lines) {
				next := strings.TrimSpace(lines[i+1])
				if strings.HasPrefix(next, "{") {
					bodyStart = i + 1
				} else {
					// No body opening found — skip (likely a forward declaration).
					continue
				}
			} else {
				continue
			}
		}

		if funcName == "" {
			continue
		}

		endLine := findPerlBraceBodyEnd(lines, bodyStart)
		var bodyLines []string
		if endLine < len(lines) {
			bodyLines = lines[i : endLine+1]
		} else {
			bodyLines = lines[i:]
		}

		functions = append(functions, PerlFunction{
			Name:      funcName,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      strings.Join(bodyLines, "\n"),
		})
	}

	return functions
}

// findPerlBraceBodyEnd finds the closing brace of a Perl subroutine body.
func findPerlBraceBodyEnd(lines []string, startIdx int) int {
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

// detectPerlFunctionCaps scans a function body and records capability evidence.
func detectPerlFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range perlPatterns.CallSites {
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

// findPerlCalls extracts unique callee names from a Perl subroutine body.
func findPerlCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	// Function-reference calls: &name(
	for _, m := range rePerlRefCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if !perlCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Direct calls: name(
	for _, m := range rePerlCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if !perlCallKeywords[name] && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	return calls
}
