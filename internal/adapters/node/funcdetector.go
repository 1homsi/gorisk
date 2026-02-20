package node

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// Function represents a JavaScript/TypeScript function found in source
type Function struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
	IsExport  bool
}

var (
	// function foo() { }  |  async function foo() { }
	reFunctionDecl = regexp.MustCompile(`(?:async\s+)?function\s+(\w+)\s*\(`)

	// const foo = function() { }  |  const foo = async function() { }
	reFunctionExpr = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(`)

	// const foo = () => { }  |  const foo = async () => { }
	reArrowFunc = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>`)

	// class methods: methodName() { }  |  async methodName() { }
	reClassMethod = regexp.MustCompile(`(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{`)

	// export function foo() { }  |  export const foo = () => { }
	reExport = regexp.MustCompile(`^\s*export\s+`)

	// Direct function calls: foo()  |  obj.method()
	reFunctionCall = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// DetectFunctions parses JavaScript/TypeScript files and returns per-function
// capability sets and call edges.
//
// This is a regex-based MVP implementation. For production, consider using
// esbuild-go or babel parser for more accurate AST analysis.
func DetectFunctions(dir string, jsFiles []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, jsFile := range jsFiles {
		fpath := filepath.Join(dir, jsFile)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		// Parse file to find function boundaries
		fileFuncs := findFunctions(string(data), fpath)

		// Parse bindings (imports/requires) for this file
		bindings, _ := ParseBindings(data, fpath)

		// Analyze each function
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

			// Detect capabilities used in this function
			detectFunctionCapabilities(&fc, fn.Body, bindings, fpath, fn.StartLine)

			// Find function calls (for call graph)
			calls := findFunctionCalls(fn.Body)
			for _, calleeName := range calls {
				// Create call edge
				calleeSym := ir.Symbol{
					Package: dir,
					Name:    calleeName,
					Kind:    "function",
				}

				edge := ir.CallEdge{
					Caller: sym,
					Callee: calleeSym,
				}
				edges = append(edges, edge)
			}

			funcs[sym.String()] = fc
		}
	}

	return funcs, edges, nil
}

// findFunctions scans source code and extracts function boundaries
func findFunctions(source, fpath string) []Function {
	var functions []Function
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		lineNo := i + 1
		var funcName string
		isExport := reExport.MatchString(line)

		// Try different function patterns
		if m := reFunctionDecl.FindStringSubmatch(line); m != nil {
			funcName = m[1]
		} else if m := reFunctionExpr.FindStringSubmatch(line); m != nil {
			funcName = m[1]
		} else if m := reArrowFunc.FindStringSubmatch(line); m != nil {
			funcName = m[1]
		} else if m := reClassMethod.FindStringSubmatch(line); m != nil {
			// Only match if it looks like a method (has proper indentation)
			if strings.HasPrefix(strings.TrimSpace(line), m[1]) {
				funcName = m[1]
			}
		}

		if funcName != "" {
			// Find function body end (naive: count braces)
			endLine := findFunctionEnd(lines, i)
			body := strings.Join(lines[i:endLine+1], "\n")

			functions = append(functions, Function{
				Name:      funcName,
				StartLine: lineNo,
				EndLine:   endLine + 1,
				Body:      body,
				IsExport:  isExport,
			})
		}
	}

	return functions
}

// findFunctionEnd finds the closing brace of a function using a state machine
// that correctly handles strings, template literals, and comments.
func findFunctionEnd(lines []string, startIdx int) int {
	type state int
	const (
		stNormal       state = iota
		stSingleQuote        // inside '...'
		stDoubleQuote        // inside "..."
		stTemplateLit        // inside `...`
		stLineComment        // inside //...
		stBlockComment       // inside /*...*/
	)

	depth := 0
	started := false
	cur := stNormal

	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		runes := []rune(line)
		n := len(runes)

		for j := 0; j < n; j++ {
			ch := runes[j]

			switch cur {
			case stNormal:
				switch ch {
				case '{':
					depth++
					started = true
				case '}':
					depth--
					if started && depth == 0 {
						return i
					}
				case '\'':
					cur = stSingleQuote
				case '"':
					cur = stDoubleQuote
				case '`':
					cur = stTemplateLit
				case '/':
					if j+1 < n {
						switch runes[j+1] {
						case '/':
							cur = stLineComment
							j++
						case '*':
							cur = stBlockComment
							j++
						}
					}
				}

			case stSingleQuote:
				switch ch {
				case '\\':
					j++ // skip escaped char
				case '\'':
					cur = stNormal
				}

			case stDoubleQuote:
				switch ch {
				case '\\':
					j++
				case '"':
					cur = stNormal
				}

			case stTemplateLit:
				switch ch {
				case '\\':
					j++
				case '`':
					cur = stNormal
				}

			case stLineComment:
				// Line comment ends at end of line — handled by outer loop reset.

			case stBlockComment:
				if ch == '*' && j+1 < n && runes[j+1] == '/' {
					cur = stNormal
					j++
				}
			}
		}

		// Line comment always resets at end of line.
		if cur == stLineComment {
			cur = stNormal
		}
	}

	// Fallback: return next 50 lines
	if startIdx+50 < len(lines) {
		return startIdx + 50
	}
	return len(lines) - 1
}

// detectFunctionCapabilities analyzes function body for capability usage
func detectFunctionCapabilities(fc *ir.FunctionCaps, body string, bindings SymbolTable, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine

	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		// Check for chained calls: require('module').method()
		if m := reChainedCall.FindAllStringSubmatch(line, -1); m != nil {
			for _, match := range m {
				module := match[1]
				method := match[2]
				detectCapabilityFromCall(fc, module, method, fpath, lineNo, 0.80)
			}
		}

		// Check for variable calls: cp.exec()
		if m := reVarCall.FindAllStringSubmatch(line, -1); m != nil {
			for _, match := range m {
				varName := match[1]
				method := match[2]

				// Resolve via bindings
				if binding, ok := bindings[varName]; ok {
					detectCapabilityFromCall(fc, binding.Module, method, fpath, lineNo, 0.85)
				}
			}
		}

		// Check for bare calls: exec() (from destructured imports)
		if m := reBareCall.FindAllStringSubmatch(line, -1); m != nil {
			for _, match := range m {
				funcName := match[1]

				// Resolve via bindings
				if binding, ok := bindings[funcName]; ok {
					// Destructured binding: {exec} from 'child_process'
					if binding.Export != "" {
						detectCapabilityFromCall(fc, binding.Module, binding.Export, fpath, lineNo, 0.85)
					}
				}
			}
		}
	}
}

// detectCapabilityFromCall checks if a module.method call matches known patterns
func detectCapabilityFromCall(fc *ir.FunctionCaps, module, method, fpath string, line int, confidence float64) {
	// First, check if the module itself grants capabilities (import-level)
	if module != "" {
		for _, cap := range nodePatterns.Imports[module] {
			fc.DirectCaps.AddWithEvidence(cap, capability.CapabilityEvidence{
				File:       fpath,
				Line:       line,
				Via:        "callSite",
				Context:    module + "." + method,
				Confidence: confidence,
			})
		}
	}

	// Check call-site patterns
	pattern := method
	if module != "" {
		pattern = module + "." + method
	}

	for _, cap := range nodePatterns.CallSites[pattern] {
		fc.DirectCaps.AddWithEvidence(cap, capability.CapabilityEvidence{
			File:       fpath,
			Line:       line,
			Via:        "callSite",
			Context:    pattern,
			Confidence: confidence,
		})
	}

	// Also check just the method name as a call-site pattern
	for _, cap := range nodePatterns.CallSites[method] {
		fc.DirectCaps.AddWithEvidence(cap, capability.CapabilityEvidence{
			File:       fpath,
			Line:       line,
			Via:        "callSite",
			Context:    method,
			Confidence: confidence * 0.9, // Lower confidence for unqualified calls
		})
	}
}

// findFunctionCalls extracts function call names from function body
func findFunctionCalls(body string) []string {
	var calls []string
	seen := make(map[string]bool)

	matches := reFunctionCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var callName string
		if m[2] != "" {
			// Method call: obj.method() -> use method name
			callName = m[2]
		} else {
			// Direct call: func()
			callName = m[1]
		}

		// Filter out common non-function calls
		if isLikelyFunction(callName) && !seen[callName] {
			calls = append(calls, callName)
			seen[callName] = true
		}
	}

	return calls
}

// isLikelyFunction filters out common keywords and built-ins
func isLikelyFunction(name string) bool {
	// Skip common keywords and built-ins
	skip := map[string]bool{
		"if": true, "else": true, "for": true, "while": true, "switch": true,
		"return": true, "new": true, "typeof": true, "instanceof": true,
		"require": true, "import": true, "export": true,
		"console": true, "log": true, "error": true, "warn": true, "info": true,
		"push": true, "pop": true, "shift": true, "unshift": true,
		"map": true, "filter": true, "reduce": true, "forEach": true,
		"slice": true, "splice": true, "concat": true, "join": true,
		"toString": true, "valueOf": true, "hasOwnProperty": true,
	}

	return !skip[name] && !strings.HasPrefix(name, "_")
}
