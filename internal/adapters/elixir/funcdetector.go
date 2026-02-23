package elixir

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// elixirFunc represents an Elixir function found in source.
type elixirFunc struct {
	Name      string
	StartLine int
	Body      string
}

var (
	// def/defp/defmacro/defmacrop name( or name do
	reElixirFuncDef = regexp.MustCompile(`^\s*(?:def|defp|defmacro|defmacrop)\s+(\w+[\?!]?)\s*(?:\(|do)`)

	// module-qualified call: Mod.func( or bare call: func(
	reElixirCall  = regexp.MustCompile(`\b(\w+)\s*\(`)
	reElixirQCall = regexp.MustCompile(`(\w+\.\w+)\s*\(`)
)

// DetectFunctions parses Elixir .ex/.exs files and returns per-function
// capability sets and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, f := range files {
		fpath := filepath.Join(dir, f)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findElixirFunctions(string(data))

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

			detectElixirFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			// Build call edges from function body.
			for _, callee := range findElixirCalls(fn.Body) {
				edges = append(edges, ir.CallEdge{
					Caller: sym,
					Callee: ir.Symbol{
						Package: dir,
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

// findElixirFunctions extracts function definitions from Elixir source.
func findElixirFunctions(source string) []elixirFunc {
	var result []elixirFunc
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reElixirFuncDef.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		name := m[1]
		startLine := i + 1
		endLine := findElixirEnd(lines, i)
		body := strings.Join(lines[i:endLine+1], "\n")

		result = append(result, elixirFunc{
			Name:      name,
			StartLine: startLine,
			Body:      body,
		})
	}

	return result
}

// findElixirEnd finds the closing `end` of an Elixir function definition.
// It counts nesting via keyword/end pairs.
func findElixirEnd(lines []string, startIdx int) int {
	depth := 0
	// Opening keywords that increase depth.
	openKws := []string{" do", "\tdo", "(do:", "do:", "fn ", "case ", "cond ", "if ", "unless ", "try ", "receive ", "with "}

	for i := startIdx; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		// Count openings on this line.
		for _, kw := range openKws {
			if strings.Contains(lines[i], kw) {
				depth++
			}
		}
		// do on its own line (inside a multi-line def block).
		if trimmed == "do" {
			depth++
		}

		// Count closings.
		if trimmed == "end" || strings.HasPrefix(trimmed, "end ") || strings.HasSuffix(trimmed, " end") || strings.HasPrefix(trimmed, "end,") || strings.HasPrefix(trimmed, "end)") {
			if depth <= 1 {
				return i
			}
			depth--
		}
	}

	// Fallback: return up to 50 lines from start.
	end := startIdx + 50
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return end
}

// detectElixirFunctionCaps scans function body lines for capability call-site patterns.
func detectElixirFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lineNo := startLine + i
		for pattern, patCaps := range elixirPatterns.CallSites {
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

// findElixirCalls returns unique function names called within a function body.
func findElixirCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	// Qualified calls first: Module.func(
	for _, m := range reElixirQCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			calls = append(calls, name)
		}
	}

	// Bare calls: func(
	for _, m := range reElixirCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if isElixirKeyword(name) || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
	}

	return calls
}

// isElixirKeyword filters Elixir keywords and common built-ins from call names.
func isElixirKeyword(name string) bool {
	skip := map[string]bool{
		"def": true, "defp": true, "defmacro": true, "defmacrop": true,
		"defmodule": true, "defstruct": true, "defprotocol": true, "defimpl": true,
		"do": true, "end": true, "if": true, "unless": true, "else": true,
		"case": true, "cond": true, "fn": true, "with": true, "for": true,
		"try": true, "catch": true, "rescue": true, "after": true, "receive": true,
		"when": true, "and": true, "or": true, "not": true, "in": true,
		"import": true, "alias": true, "use": true, "require": true,
		"raise": true, "throw": true, "exit": true,
		"true": true, "false": true, "nil": true,
	}
	return skip[name]
}
