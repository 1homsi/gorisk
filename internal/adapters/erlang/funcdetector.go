package erlang

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// erlFunc represents an Erlang function found in source.
type erlFunc struct {
	Name      string
	StartLine int
	Body      string
}

var (
	// Erlang functions start at column 0 with a lowercase letter.
	reErlFuncDef = regexp.MustCompile(`^([a-z]\w*)\s*\(`)

	// Remote call: module:function( or local call: function(
	reErlRemoteCall = regexp.MustCompile(`(\w+):(\w+)\s*\(`)
	reErlLocalCall  = regexp.MustCompile(`\b(\w+)\s*\(`)
)

// DetectFunctions parses Erlang .erl/.hrl files and returns per-function
// capability sets and call edges.
func DetectFunctions(dir, pkgName string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, f := range files {
		fpath := filepath.Join(dir, f)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findErlFunctions(string(data))

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

			detectErlFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			// Build call edges from function body.
			for _, callee := range findErlCalls(fn.Body) {
				edges = append(edges, ir.CallEdge{
					Caller: sym,
					Callee: ir.Symbol{
						Package: pkgName,
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

// findErlFunctions extracts function definitions from Erlang source.
// Each Erlang function clause ends with a period at top-level.
func findErlFunctions(source string) []erlFunc {
	var result []erlFunc
	lines := strings.Split(source, "\n")

	// Track which function names we have already seen so we merge clauses.
	seen := make(map[string]int) // name → index in result

	for i, line := range lines {
		m := reErlFuncDef.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		name := m[1]
		startLine := i + 1

		// Collect the clause body until the period that ends it.
		endLine := findErlClauseEnd(lines, i)
		body := strings.Join(lines[i:endLine+1], "\n")

		if idx, exists := seen[name]; exists {
			// Merge into existing function entry.
			result[idx].Body += "\n" + body
		} else {
			seen[name] = len(result)
			result = append(result, erlFunc{
				Name:      name,
				StartLine: startLine,
				Body:      body,
			})
		}
	}

	return result
}

// findErlClauseEnd finds the line where the current Erlang function clause ends.
// Erlang clauses terminate with a period (".") at the top-level (not inside
// strings or comments).
func findErlClauseEnd(lines []string, startIdx int) int {
	inString := false
	inComment := false

	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		inComment = false // Erlang line comments reset each line

		for j := 0; j < len(line); j++ {
			ch := line[j]

			if inString {
				switch ch {
				case '\\':
					j++ // skip escaped char
				case '"':
					inString = false
				}
				continue
			}

			if inComment {
				break
			}

			switch ch {
			case '"':
				inString = true
			case '%':
				inComment = true
			case '.':
				// A period followed by whitespace/EOF ends the clause.
				if j+1 >= len(line) || line[j+1] == ' ' || line[j+1] == '\t' || line[j+1] == '\r' || line[j+1] == '\n' {
					return i
				}
			}
		}
	}

	end := startIdx + 50
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return end
}

// detectErlFunctionCaps scans function body lines for capability call-site patterns.
func detectErlFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lineNo := startLine + i
		for pattern, patCaps := range erlangPatterns.CallSites {
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

// findErlCalls returns unique function names called within an Erlang function body.
func findErlCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	// Remote calls: module:func( → use "module:func" as callee name.
	for _, m := range reErlRemoteCall.FindAllStringSubmatch(body, -1) {
		name := m[1] + ":" + m[2]
		if !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Local calls: func(
	for _, m := range reErlLocalCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if isErlKeyword(name) || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
	}

	return calls
}

// isErlKeyword filters Erlang reserved words and common built-ins.
func isErlKeyword(name string) bool {
	skip := map[string]bool{
		"after": true, "and": true, "andalso": true, "band": true, "begin": true,
		"bnot": true, "bor": true, "bsl": true, "bsr": true, "bxor": true,
		"case": true, "catch": true, "cond": true, "div": true, "end": true,
		"fun": true, "if": true, "let": true, "not": true, "of": true,
		"or": true, "orelse": true, "receive": true, "rem": true, "try": true,
		"when": true, "xor": true,
		// common built-in functions
		"erlang": true, "lists": true, "io": true, "file": true, "os": true,
		"spawn": true, "self": true, "send": true, "is_atom": true,
		"is_binary": true, "is_integer": true, "is_list": true, "is_tuple": true,
		"length": true, "hd": true, "tl": true, "element": true, "tuple_size": true,
	}
	return skip[name]
}
