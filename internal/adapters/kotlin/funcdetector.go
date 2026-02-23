package kotlin

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// KotlinFunction represents a Kotlin function found in source.
type KotlinFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// reKotlinFunc matches Kotlin function declarations.
	reKotlinFunc = regexp.MustCompile(`^\s*(?:(?:public|private|protected|internal|open|override|abstract|final|suspend|inline|operator|infix|external|tailrec)\s+)*fun\s+(?:<[^>]*>\s*)?(\w+)\s*\(`)

	// reKotlinCall matches function/method calls: obj.method( or func(
	reKotlinCall = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// kotlinKeywords are identifiers to skip in call detection.
var kotlinKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "when": true, "try": true,
	"catch": true, "new": true, "return": true, "class": true, "interface": true,
	"object": true, "import": true, "package": true, "throw": true,
	"finally": true, "else": true, "do": true, "break": true, "continue": true,
	"is": true, "as": true, "in": true, "fun": true, "val": true, "var": true,
}

// DetectFunctions parses Kotlin source files and returns per-function capability
// sets and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, ktFile := range files {
		fpath := filepath.Join(dir, ktFile)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findKotlinFunctions(string(data))

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

			detectKotlinFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findKotlinCalls(fn.Body)
			for _, calleeName := range calls {
				calleeSym := ir.Symbol{
					Package: dir,
					Name:    calleeName,
					Kind:    "function",
				}
				edges = append(edges, ir.CallEdge{Caller: sym, Callee: calleeSym})
			}

			funcs[sym.String()] = fc
		}
	}

	return funcs, edges, nil
}

// findKotlinFunctions scans Kotlin source and extracts function boundaries.
func findKotlinFunctions(source string) []KotlinFunction {
	var functions []KotlinFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reKotlinFunc.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if kotlinKeywords[name] {
			continue
		}

		// Handle expression functions (fun foo() = expr) — treat entire line as body.
		if strings.Contains(line, "=") && !strings.Contains(line, "{") {
			functions = append(functions, KotlinFunction{
				Name:      name,
				StartLine: i + 1,
				EndLine:   i + 1,
				Body:      line,
			})
			continue
		}

		// Find the opening brace (may be on same or next non-blank line).
		braceIdx := i
		if !strings.Contains(line, "{") {
			found := false
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if strings.Contains(lines[j], "{") {
					braceIdx = j
					found = true
					break
				}
				if strings.TrimSpace(lines[j]) != "" {
					break
				}
			}
			if !found {
				// Abstract or interface function with no body.
				continue
			}
		}

		endLine := findKotlinBraceEnd(lines, braceIdx)
		body := strings.Join(lines[i:endLine+1], "\n")

		functions = append(functions, KotlinFunction{
			Name:      name,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      body,
		})
	}

	return functions
}

// findKotlinBraceEnd finds the closing brace of a Kotlin block.
func findKotlinBraceEnd(lines []string, startIdx int) int {
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
	if startIdx+100 < len(lines) {
		return startIdx + 100
	}
	return len(lines) - 1
}

// detectKotlinFunctionCaps scans a function body for capability-indicating patterns.
func detectKotlinFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range kotlinPatterns.CallSites {
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

// findKotlinCalls extracts called function/method names from a function body.
func findKotlinCalls(body string) []string {
	var calls []string
	seen := make(map[string]bool)

	matches := reKotlinCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var name string
		if m[2] != "" {
			name = m[2]
		} else {
			name = m[1]
		}
		if !kotlinKeywords[name] && !seen[name] && name != "" {
			calls = append(calls, name)
			seen[name] = true
		}
	}
	return calls
}
