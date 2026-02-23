package ruby

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// rbFunc represents a Ruby method found in source.
type rbFunc struct {
	Name      string
	StartLine int
	Body      string
}

var (
	// def name(  |  def self.name(  |  def name?  |  def name!
	reRbDef = regexp.MustCompile(`(?m)^\s*def\s+(?:self\.)?(\w+[\?!]?)\s*(?:\(|$|\s)`)

	// bare call: name(  or  name arg (method call without parens)
	reRbCall = regexp.MustCompile(`\b(\w+)\s*\(`)
)

// keywords that open a new block and must be matched with an `end`
var rbBlockOpeners = regexp.MustCompile(
	`\b(?:def|class|module|if|unless|case|while|until|for|begin|do)\b`,
)

// DetectFunctions parses Ruby files and returns per-function capability sets
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

		fileFuncs := findRbFunctions(string(data))

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

			detectRbFunctionCapabilities(&fc, fn.Body, fpath, fn.StartLine)

			for _, callee := range findRbCalls(fn.Body) {
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

// findRbFunctions extracts method definitions from Ruby source.
// Body extraction uses keyword counting (def/do/begin/… vs end).
func findRbFunctions(source string) []rbFunc {
	var result []rbFunc
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		m := reRbDef.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		name := m[1]
		startLine := i + 1

		// Walk forward counting opens vs ends to find the closing `end`.
		depth := 0
		var bodyLines []string
		bodyLines = append(bodyLines, line)

		// Count openers on the def line itself (the def keyword counts as +1).
		depth += countRbOpeners(line)
		depth -= countRbEnds(line)

		j := i + 1
		for j < len(lines) && depth > 0 {
			l := lines[j]
			bodyLines = append(bodyLines, l)
			depth += countRbOpeners(l)
			depth -= countRbEnds(l)
			j++
		}

		result = append(result, rbFunc{
			Name:      name,
			StartLine: startLine,
			Body:      strings.Join(bodyLines, "\n"),
		})
	}

	return result
}

// countRbOpeners counts block-opening keywords in a line.
func countRbOpeners(line string) int {
	stripped := stripRbStrings(line)
	return len(rbBlockOpeners.FindAllString(stripped, -1))
}

// countRbEnds counts `end` keywords in a line.
func countRbEnds(line string) int {
	stripped := stripRbStrings(line)
	re := regexp.MustCompile(`\bend\b`)
	return len(re.FindAllString(stripped, -1))
}

// stripRbStrings removes string literals to avoid false keyword matches.
func stripRbStrings(line string) string {
	// Remove single-quoted strings.
	reSingle := regexp.MustCompile(`'[^']*'`)
	line = reSingle.ReplaceAllString(line, `''`)
	// Remove double-quoted strings.
	reDouble := regexp.MustCompile(`"[^"]*"`)
	line = reDouble.ReplaceAllString(line, `""`)
	// Remove inline comments.
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return line
}

// detectRbFunctionCapabilities scans function body lines for call-site patterns.
func detectRbFunctionCapabilities(fc *ir.FunctionCaps, body, fpath string, startLine int) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lineNo := startLine + i
		for pattern, caps := range rubyPatterns.CallSites {
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

// findRbCalls returns unique method names called in the body.
func findRbCalls(body string) []string {
	seen := make(map[string]bool)
	var calls []string

	matches := reRbCall.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		name := m[1]
		if isRbKeyword(name) || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
	}
	return calls
}

// isRbKeyword filters Ruby keywords from call names.
func isRbKeyword(name string) bool {
	skip := map[string]bool{
		"if": true, "unless": true, "else": true, "elsif": true, "then": true,
		"while": true, "until": true, "for": true, "do": true, "begin": true,
		"rescue": true, "ensure": true, "end": true, "return": true, "yield": true,
		"raise": true, "require": true, "require_relative": true, "load": true,
		"class": true, "module": true, "def": true, "self": true, "super": true,
		"true": true, "false": true, "nil": true, "and": true, "or": true,
		"not": true, "in": true, "case": true, "when": true,
		"puts": true, "print": true, "p": true,
	}
	return skip[name]
}
