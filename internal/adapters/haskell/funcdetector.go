package haskell

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// HaskellFunction represents a top-level Haskell function definition.
type HaskellFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// Matches top-level function definitions (not indented).
	// Examples: main = ...,  myFunc x y = ...,  go acc = ...
	reFuncDef = regexp.MustCompile(`^([a-z_]\w*)\s+(?:[^\s=|\\()\[\]{},]+\s*)*(?:=|where)`)

	// Simpler binding: foo = ...
	reSimpleBinding = regexp.MustCompile(`^([a-z_]\w*)\s*=\s*`)

	// Type signature: foo :: ...
	reTypeSig = regexp.MustCompile(`^([a-z_]\w*)\s*::`)

	// Function application call: foo bar  (identifier followed by space then non-operator)
	reHsCall = regexp.MustCompile(`\b([a-zA-Z]\w*(?:\.\w+)*)\s+`)

	// Qualified call: Module.function
	reHsQualCall = regexp.MustCompile(`\b([A-Z]\w*)\.([a-z]\w*)\s*`)
)

// DetectFunctions parses Haskell source files and returns per-function capability
// sets and call edges.
func DetectFunctions(dir, pkgName string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, fname := range files {
		fpath := filepath.Join(dir, fname)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		// First pass: collect type signatures so we know which names are functions.
		knownSigs := collectHaskellTypeSigs(string(data))

		fileFuncs := findHaskellFunctions(string(data), knownSigs)

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

			detectHaskellFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findHaskellFunctionCalls(fn.Body)
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

// collectHaskellTypeSigs does a first pass to find all top-level type signatures.
func collectHaskellTypeSigs(source string) map[string]bool {
	sigs := make(map[string]bool)
	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		if m := reTypeSig.FindStringSubmatch(line); m != nil {
			sigs[m[1]] = true
		}
	}
	return sigs
}

// findHaskellFunctions scans Haskell source for top-level function definitions.
func findHaskellFunctions(source string, knownSigs map[string]bool) []HaskellFunction {
	var functions []HaskellFunction
	lines := strings.Split(source, "\n")

	seen := make(map[string]bool)

	for i, line := range lines {
		lineNo := i + 1

		// Skip indented lines (not top-level).
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Skip line comments.
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		// Skip module/import/type/data/newtype/class/instance declarations.
		for _, kw := range []string{"module ", "import ", "type ", "data ", "newtype ", "class ", "instance ", "where", "infixl", "infixr", "infix"} {
			if strings.HasPrefix(trimmed, kw) {
				goto nextLine
			}
		}

		{
			var fnName string

			// Try to match a function definition.
			if m := reFuncDef.FindStringSubmatch(line); m != nil {
				fnName = m[1]
			} else if m := reSimpleBinding.FindStringSubmatch(line); m != nil {
				// Only accept if we have a type sig, or if the name looks like a function.
				if knownSigs[m[1]] {
					fnName = m[1]
				}
			}

			if fnName != "" && !seen[fnName] {
				seen[fnName] = true
				body, endIdx := collectIndentedBody(lines, i)
				functions = append(functions, HaskellFunction{
					Name:      fnName,
					StartLine: lineNo,
					EndLine:   endIdx + 1,
					Body:      body,
				})
			}
		}

	nextLine:
	}

	return functions
}

// collectIndentedBody collects the definition body of a Haskell function.
// Body lines are those that are more indented than the start line.
func collectIndentedBody(lines []string, startIdx int) (string, int) {
	if startIdx >= len(lines) {
		return "", startIdx
	}
	startIndent := countLeadingSpaces(lines[startIdx])
	var body []string
	body = append(body, lines[startIdx])
	endIdx := startIdx

	for i := startIdx + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			body = append(body, l)
			continue
		}
		indent := countLeadingSpaces(l)
		if indent <= startIndent {
			break
		}
		body = append(body, l)
		endIdx = i
	}

	return strings.Join(body, "\n"), endIdx
}

// countLeadingSpaces counts the leading whitespace, treating tabs as 4 spaces.
func countLeadingSpaces(s string) int {
	count := 0
	for _, ch := range s {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 4
		default:
			return count
		}
	}
	return count
}

// detectHaskellFunctionCaps scans a function body for capability-relevant patterns.
func detectHaskellFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		for pattern, patCaps := range haskellPatterns.CallSites {
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

// findHaskellFunctionCalls extracts called function names from a function body.
func findHaskellFunctionCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	addCall := func(name string) {
		if name != "" && isLikelyHaskellFunction(name) && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Qualified calls: Module.func
	for _, m := range reHsQualCall.FindAllStringSubmatch(body, -1) {
		addCall(m[1] + "." + m[2])
		addCall(m[2])
	}

	// Function application calls.
	for _, m := range reHsCall.FindAllStringSubmatch(body, -1) {
		addCall(m[1])
	}

	return calls
}

// isLikelyHaskellFunction filters out Haskell keywords.
func isLikelyHaskellFunction(name string) bool {
	skip := map[string]bool{
		"if": true, "then": true, "else": true, "do": true, "let": true,
		"in": true, "where": true, "case": true, "of": true, "import": true,
		"module": true, "data": true, "type": true, "newtype": true, "class": true,
		"instance": true, "deriving": true, "qualified": true, "as": true,
		"hiding": true, "infixl": true, "infixr": true, "infix": true,
		"return": true, "pure": true, "True": true, "False": true,
	}
	return !skip[name]
}
