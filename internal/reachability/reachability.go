package reachability

import (
	"fmt"

	"github.com/1homsi/gorisk/internal/capability"
)

// ReachabilityReport describes how a dependency's capabilities are reachable
// from the project's source code.
type ReachabilityReport struct {
	Package       string
	ReachableCaps capability.CapabilitySet
	Reachable     bool
}

// Analyze runs reachability analysis for the project rooted at dir.
// lang selects the implementation: "go", "node", or "auto".
func Analyze(dir, lang string) ([]ReachabilityReport, error) {
	switch lang {
	case "go":
		return analyzeGo(dir)
	case "node":
		return analyzeNode(dir)
	default:
		return nil, fmt.Errorf("reachability: unsupported language %q (supported: go, node)", lang)
	}
}
