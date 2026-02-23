package clojure

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// cljFunc represents a Clojure function found in source.
type cljFunc struct {
	Name      string
	StartLine int
	Body      string
}

var (
	// (defn/defn-/defmacro/defmulti name
	reCljFuncDef = regexp.MustCompile(`^\s*\((?:defn|defn-|defmacro|defmulti)\s+([\w\-\?\!\*\+\>\<=]+)\s*`)

	// any function call: (funcname ...
	reCljCall = regexp.MustCompile(`\(([\w\-\?\!\*\+\>\<=\/]+)\s*`)
)

// DetectFunctions parses Clojure .clj/.cljs/.cljc files and returns
// per-function capability sets and call edges.
func DetectFunctions(dir string, files []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, f := range files {
		fpath := filepath.Join(dir, f)
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		fileFuncs := findCljFunctions(string(data))

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

			detectCljFunctionCaps(&fc, fn.Body, fpath, fn.StartLine)

			// Build call edges from function body.
			for _, callee := range findCljCalls(fn.Body) {
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

// findCljFunctions extracts function definitions from Clojure source using
// parenthesis-depth counting.
func findCljFunctions(source string) []cljFunc {
	var result []cljFunc
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reCljFuncDef.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		name := m[1]
		startLine := i + 1
		endLine := findParenEnd(lines, i)
		body := strings.Join(lines[i:endLine+1], "\n")

		result = append(result, cljFunc{
			Name:      name,
			StartLine: startLine,
			Body:      body,
		})
	}

	return result
}

// findParenEnd finds the line where the opening paren from startIdx closes.
func findParenEnd(lines []string, startIdx int) int {
	depth := 0
	inString := false
	inLineComment := false

	for i := startIdx; i < len(lines); i++ {
		inLineComment = false
		for _, ch := range lines[i] {
			if inLineComment {
				break
			}
			if inString {
				if ch == '"' {
					inString = false
				}
				continue
			}
			switch ch {
			case ';':
				inLineComment = true
			case '"':
				inString = true
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
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

// detectCljFunctionCaps scans function body lines for capability call-site patterns.
func detectCljFunctionCaps(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lineNo := startLine + i
		for pattern, patCaps := range clojurePatterns.CallSites {
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

// findCljCalls returns unique function names called within a Clojure function body.
func findCljCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	for _, m := range reCljCall.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if isCljKeyword(name) || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
	}

	return calls
}

// isCljKeyword filters Clojure special forms and common built-ins.
func isCljKeyword(name string) bool {
	skip := map[string]bool{
		"defn": true, "defn-": true, "defmacro": true, "defmulti": true,
		"defmethod": true, "def": true, "defonce": true, "defrecord": true,
		"defprotocol": true, "deftype": true, "ns": true, "in-ns": true,
		"let": true, "letfn": true, "if": true, "if-let": true, "if-not": true,
		"when": true, "when-let": true, "when-not": true, "cond": true,
		"condp": true, "case": true, "do": true, "fn": true, "loop": true,
		"recur": true, "and": true, "or": true, "not": true, "for": true,
		"doseq": true, "dotimes": true, "while": true, "throw": true,
		"try": true, "catch": true, "finally": true,
		"require": true, "use": true, "import": true, "refer": true,
		"quote": true, "var": true, "new": true,
		"->": true, "->>": true, "as->": true,
		"map": true, "filter": true, "reduce": true, "apply": true,
		"assoc": true, "dissoc": true, "get": true, "conj": true, "cons": true,
		"first": true, "second": true, "rest": true, "next": true, "last": true,
		"count": true, "empty?": true, "seq": true, "vec": true, "list": true,
		"str": true, "println": true, "print": true, "prn": true,
	}
	return skip[name]
}
