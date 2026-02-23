package rust

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// RustFunction represents a Rust function found in source.
type RustFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// Matches: fn foo(  |  pub fn foo(  |  pub(crate) fn foo(  |  async fn foo(  |  unsafe fn foo(  |  pub async unsafe fn foo<T>(
	reFnDecl = regexp.MustCompile(`^\s*(?:pub(?:\s*\([\w\s:,]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*(?:<[^>]*)?\s*\(`)

	// Matches: impl Foo {  |  impl<T> Foo<T> {
	reImplBlock = regexp.MustCompile(`^\s*impl(?:<[^>]*)?\s+(\w+)`)

	// Direct function call: foo(
	reCallDirect = regexp.MustCompile(`\b(\w+)\s*\(`)

	// Qualified call: Foo::bar(  or  foo::bar(
	reCallQualified = regexp.MustCompile(`(\w+)::(\w+)\s*\(`)

	// Method call: foo.bar(
	reCallMethod = regexp.MustCompile(`(\w+)\.(\w+)\s*\(`)
)

// DetectFunctions parses Rust source files and returns per-function capability
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

		fileFuncs := findRustFunctions(string(data))

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

			detectRustFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findRustFunctionCalls(fn.Body)
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

// findRustFunctions scans Rust source code and extracts function definitions.
// It handles top-level functions and methods inside impl blocks.
func findRustFunctions(source string) []RustFunction {
	var functions []RustFunction
	lines := strings.Split(source, "\n")

	// Track current impl type so methods can be named "Type::method".
	currentImpl := ""

	for i, line := range lines {
		lineNo := i + 1

		trimmed := strings.TrimSpace(line)

		// Skip line comments.
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Skip block comment opens (best-effort; not full state machine).
		if strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Detect impl blocks to namespace method names.
		if m := reImplBlock.FindStringSubmatch(line); m != nil {
			currentImpl = m[1]
		}

		if m := reFnDecl.FindStringSubmatch(line); m != nil {
			fnName := m[1]
			if currentImpl != "" && strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}

			// Build qualified name for methods inside impl blocks.
			qualifiedName := fnName
			if currentImpl != "" {
				// Heuristic: if the fn line is indented, it is inside the impl block.
				if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
					qualifiedName = currentImpl + "::" + fnName
				}
			}

			endLine := findBraceEnd(lines, i)
			body := strings.Join(lines[i:endLine+1], "\n")

			functions = append(functions, RustFunction{
				Name:      qualifiedName,
				StartLine: lineNo,
				EndLine:   endLine + 1,
				Body:      body,
			})
		}
	}

	return functions
}

// findBraceEnd finds the closing brace of a Rust function body using brace counting.
func findBraceEnd(lines []string, startIdx int) int {
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

// detectRustFunctionCaps scans a function body for capability-relevant patterns.
func detectRustFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for pattern, patCaps := range rustPatterns.CallSites {
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

// findRustFunctionCalls extracts called function/method names from a function body.
func findRustFunctionCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	addCall := func(name string) {
		if name != "" && isLikelyRustFunction(name) && !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Qualified calls: foo::bar(
	for _, m := range reCallQualified.FindAllStringSubmatch(body, -1) {
		addCall(m[1] + "::" + m[2])
		addCall(m[2])
	}

	// Method calls: foo.bar(
	for _, m := range reCallMethod.FindAllStringSubmatch(body, -1) {
		addCall(m[2])
	}

	// Direct calls: foo(
	for _, m := range reCallDirect.FindAllStringSubmatch(body, -1) {
		addCall(m[1])
	}

	return calls
}

// isLikelyRustFunction filters out Rust keywords and common control-flow tokens.
func isLikelyRustFunction(name string) bool {
	skip := map[string]bool{
		"if": true, "else": true, "for": true, "while": true, "loop": true,
		"match": true, "return": true, "let": true, "mut": true, "use": true,
		"pub": true, "fn": true, "impl": true, "struct": true, "enum": true,
		"trait": true, "mod": true, "type": true, "where": true, "async": true,
		"await": true, "unsafe": true, "extern": true, "move": true, "dyn": true,
		"in": true, "ref": true, "self": true, "super": true, "crate": true,
		"Some": true, "None": true, "Ok": true, "Err": true,
		"true": true, "false": true,
	}
	return !skip[name]
}
