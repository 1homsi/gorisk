package lua

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// luaFunc represents a Lua function found in source.
type luaFunc struct {
	Name      string
	StartLine int
	Body      string
}

var (
	// function name(  |  function obj.method(  |  function obj:method(
	reLuaFuncDecl = regexp.MustCompile(`(?m)^\s*function\s+([\w\.]+|[\w]+:[\w]+)\s*\(`)

	// local function name(
	reLuaLocalFunc = regexp.MustCompile(`(?m)^\s*local\s+function\s+(\w+)\s*\(`)

	// name = function(
	reLuaFuncExpr = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*function\s*\(`)

	// function call: name(  or  obj:method(
	reLuaCall = regexp.MustCompile(`\b(\w+)\s*\(`)
)

// luaBlockOpeners matches keywords that open a new block requiring an `end`.
var reLuaOpener = regexp.MustCompile(`\b(?:function|if|do|for|while|repeat)\b`)

// luaBlockClosers matches `end` or `until` (repeat..until closes without `end`).
var reLuaEnd = regexp.MustCompile(`\bend\b`)
var reLuaUntil = regexp.MustCompile(`\buntil\b`)

// DetectFunctions parses Lua files and returns per-function capability sets
// and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, f := range files {
		fpath := filepath.Join(dir, f)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findLuaFunctions(string(data))

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

			detectLuaFunctionCapabilities(&fc, fn.Body, fpath, fn.StartLine)

			for _, callee := range findLuaCalls(fn.Body) {
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

// findLuaFunctions extracts function definitions from Lua source.
// Body extraction uses keyword counting (function/if/do/for/while vs end/until).
func findLuaFunctions(source string) []luaFunc {
	var result []luaFunc
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		var name string

		if m := reLuaLocalFunc.FindStringSubmatch(line); m != nil {
			name = m[1]
		} else if m := reLuaFuncDecl.FindStringSubmatch(line); m != nil {
			name = m[1]
		} else if m := reLuaFuncExpr.FindStringSubmatch(line); m != nil {
			name = m[1]
		} else {
			continue
		}

		startLine := i + 1

		// Walk forward counting openers vs ends to find the closing `end`.
		depth := 0
		var bodyLines []string
		bodyLines = append(bodyLines, line)

		depth += countLuaOpeners(line)
		depth -= countLuaEnds(line)

		j := i + 1
		for j < len(lines) && depth > 0 {
			l := lines[j]
			bodyLines = append(bodyLines, l)
			depth += countLuaOpeners(l)
			depth -= countLuaEnds(l)
			j++
		}

		result = append(result, luaFunc{
			Name:      name,
			StartLine: startLine,
			Body:      strings.Join(bodyLines, "\n"),
		})
	}

	return result
}

// countLuaOpeners counts block-opening keywords in a line (strips strings first).
func countLuaOpeners(line string) int {
	stripped := stripLuaStrings(line)
	return len(reLuaOpener.FindAllString(stripped, -1))
}

// countLuaEnds counts `end` and `until` keywords in a line.
func countLuaEnds(line string) int {
	stripped := stripLuaStrings(line)
	return len(reLuaEnd.FindAllString(stripped, -1)) +
		len(reLuaUntil.FindAllString(stripped, -1))
}

// stripLuaStrings removes string literals and comments to avoid false matches.
func stripLuaStrings(line string) string {
	// Remove double-quoted strings.
	reDouble := regexp.MustCompile(`"[^"]*"`)
	line = reDouble.ReplaceAllString(line, `""`)
	// Remove single-quoted strings.
	reSingle := regexp.MustCompile(`'[^']*'`)
	line = reSingle.ReplaceAllString(line, `''`)
	// Remove inline comments (--).
	if idx := strings.Index(line, "--"); idx >= 0 {
		line = line[:idx]
	}
	return line
}

// detectLuaFunctionCapabilities scans function body lines for call-site patterns.
func detectLuaFunctionCapabilities(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lineNo := startLine + i
		for pattern, caps := range luaPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range caps {
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

// findLuaCalls returns unique function names called in the body.
func findLuaCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	matches := reLuaCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		name := m[1]
		if isLuaKeyword(name) || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
	}
	return calls
}

// isLuaKeyword filters Lua keywords from call names.
func isLuaKeyword(name string) bool {
	skip := map[string]bool{
		"if": true, "then": true, "else": true, "elseif": true, "end": true,
		"while": true, "do": true, "for": true, "repeat": true, "until": true,
		"function": true, "local": true, "return": true, "break": true,
		"and": true, "or": true, "not": true, "in": true,
		"true": true, "false": true, "nil": true,
		"print": true, "tostring": true, "tonumber": true, "type": true,
		"pairs": true, "ipairs": true, "next": true, "select": true,
		"pcall": true, "xpcall": true, "error": true,
	}
	return skip[name]
}
