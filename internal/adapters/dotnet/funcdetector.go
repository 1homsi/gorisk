package dotnet

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// dotnetFunction represents a C# method found in source.
type dotnetFunction struct {
	Name      string
	StartLine int
	EndLine   int
	Body      string
}

var (
	// Matches C# method declarations with at least one access/modifier keyword:
	//   public void Foo(...)
	//   private static async Task<string> Bar(...)
	//   protected override bool Baz(...)
	reMethodDecl = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|partial|extern|new|readonly|unsafe)\s+)+` +
			`(?:\w+(?:<[^>]*>)?(?:\[\])*\s+)(\w+)\s*\(`,
	)

	// Direct call: foo(  or  obj.Method(
	reCallSite = regexp.MustCompile(`\b(\w+)(?:\.(\w+))?\s*\(`)
)

// skipDotnetKeywords lists identifiers that are not real method calls.
var skipDotnetKeywords = map[string]bool{
	"if": true, "for": true, "foreach": true, "while": true, "switch": true,
	"catch": true, "return": true, "new": true, "class": true, "struct": true,
	"interface": true, "using": true, "namespace": true, "import": true,
	"package": true, "throw": true, "typeof": true, "sizeof": true,
	"checked": true, "unchecked": true, "lock": true, "fixed": true,
}

// DetectFunctions parses C# source files and returns per-function
// capability sets and call edges.
func DetectFunctions(dir, pkgName string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, file := range files {
		fpath := filepath.Join(dir, file)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findDotnetFunctions(string(data))

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

			detectDotnetFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			calls := findDotnetCalls(fn.Body)
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

// findDotnetFunctions scans C# source code and extracts method boundaries.
func findDotnetFunctions(source string) []dotnetFunction {
	var functions []dotnetFunction
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reMethodDecl.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		methodName := m[1]
		if skipDotnetKeywords[methodName] {
			continue
		}
		endLine := findDotnetBraceBodyEnd(lines, i)
		body := strings.Join(lines[i:endLine+1], "\n")
		functions = append(functions, dotnetFunction{
			Name:      methodName,
			StartLine: i + 1,
			EndLine:   endLine + 1,
			Body:      body,
		})
	}

	return functions
}

// findDotnetBraceBodyEnd finds the closing brace of a brace-delimited body.
func findDotnetBraceBodyEnd(lines []string, startIdx int) int {
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

// detectDotnetFunctionCaps scans a method body for capability evidence using
// the dotnetPatterns call-site map.
func detectDotnetFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	lineNo := startLine
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		for pattern, patCaps := range dotnetPatterns.CallSites {
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

// findDotnetCalls extracts called method/function names from a method body.
func findDotnetCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	matches := reCallSite.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var name string
		if m[2] != "" {
			name = m[2]
		} else {
			name = m[1]
		}
		if name != "" && !skipDotnetKeywords[name] && !seen[name] {
			calls = append(calls, name)
			seen[name] = true
		}
	}
	return calls
}
