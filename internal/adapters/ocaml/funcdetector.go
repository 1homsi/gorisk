package ocaml

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// OCamlFunction represents an OCaml let-binding found in source.
type OCamlFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// Matches: let foo ...  |  let rec foo ...
	reLetDef = regexp.MustCompile(`^\s*let\s+(?:rec\s+)?([a-z_]\w*)\s*`)

	// Function application call: foo arg
	reOCamlCall = regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\.\w+)*)\s+`)

	// Module-qualified call: Module.func
	reOCamlQualCall = regexp.MustCompile(`\b([A-Z]\w*)\.([a-z_]\w*)\s*`)
)

// DetectFunctions parses OCaml source files and returns per-function capability
// sets and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, fname := range files {
		fpath := filepath.Join(dir, fname)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findOCamlFunctions(string(data))

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

			detectOCamlFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findOCamlFunctionCalls(fn.Body)
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

// findOCamlFunctions scans OCaml source for top-level let-bindings.
func findOCamlFunctions(source string) []OCamlFunction {
	var functions []OCamlFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		lineNo := i + 1

		trimmed := strings.TrimSpace(line)

		// Skip comments.
		if strings.HasPrefix(trimmed, "(*") {
			continue
		}

		// Only look at top-level bindings (not indented more than reasonable).
		// We allow a small indent for module-level lets inside structures.
		indent := countOCamlLeadingSpaces(line)
		if indent > 2 {
			continue
		}

		if m := reLetDef.FindStringSubmatch(line); m != nil {
			fnName := m[1]
			// Skip operator definitions like "let () = ..." (main expressions).
			if fnName == "" {
				continue
			}

			body, endIdx := collectOCamlBody(lines, i)
			functions = append(functions, OCamlFunction{
				Name:      fnName,
				StartLine: lineNo,
				EndLine:   endIdx + 1,
				Body:      body,
			})
		}
	}

	return functions
}

// collectOCamlBody collects the body of an OCaml let-binding.
// The body ends at the next top-level `let` at the same indent level, or `;;`.
func collectOCamlBody(lines []string, startIdx int) (string, int) {
	if startIdx >= len(lines) {
		return "", startIdx
	}

	startIndent := countOCamlLeadingSpaces(lines[startIdx])
	var body []string
	body = append(body, lines[startIdx])
	endIdx := startIdx

	for i := startIdx + 1; i < len(lines); i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)

		// Double semicolon terminates a top-level expression.
		if trimmed == ";;" {
			body = append(body, l)
			endIdx = i
			break
		}

		if trimmed == "" {
			body = append(body, l)
			continue
		}

		indent := countOCamlLeadingSpaces(l)

		// A new top-level let at same or lower indent signals end of body.
		if indent <= startIndent && reLetDef.MatchString(l) {
			break
		}

		body = append(body, l)
		endIdx = i
	}

	return strings.Join(body, "\n"), endIdx
}

// countOCamlLeadingSpaces counts the leading whitespace (tabs = 2 for OCaml convention).
func countOCamlLeadingSpaces(s string) int {
	count := 0
	for _, ch := range s {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 2
		default:
			return count
		}
	}
	return count
}

// detectOCamlFunctionCaps scans a function body for capability-relevant patterns.
func detectOCamlFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "(*") {
			continue
		}
		for pattern, patCaps := range ocamlPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					fc.DirectCaps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       fpath,
						Line:       lineNo,
						Context:    trimmed,
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}

// findOCamlFunctionCalls extracts called function names from a function body.
func findOCamlFunctionCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	addCall := func(name string) {
		if name != "" && isLikelyOCamlFunction(name) && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Module-qualified calls: Module.func
	for _, m := range reOCamlQualCall.FindAllStringSubmatch(body, -1) {
		addCall(m[1] + "." + m[2])
		addCall(m[2])
	}

	// Function application.
	for _, m := range reOCamlCall.FindAllStringSubmatch(body, -1) {
		addCall(m[1])
	}

	return calls
}

// isLikelyOCamlFunction filters out OCaml keywords.
func isLikelyOCamlFunction(name string) bool {
	skip := map[string]bool{
		"let": true, "rec": true, "in": true, "fun": true, "function": true,
		"if": true, "then": true, "else": true, "match": true, "with": true,
		"type": true, "val": true, "module": true, "struct": true, "sig": true,
		"end": true, "open": true, "include": true, "exception": true,
		"begin": true, "do": true, "done": true, "for": true, "while": true,
		"and": true, "or": true, "not": true, "mod": true, "land": true,
		"lor": true, "lxor": true, "lsl": true, "lsr": true, "asr": true,
		"true": true, "false": true, "when": true, "try": true,
	}
	return !skip[name]
}
