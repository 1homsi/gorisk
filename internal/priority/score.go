// Package priority computes composite risk scores combining capability,
// reachability, CVE, and taint analysis signals.
package priority

import (
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/taint"
)

// CompositeScore combines multiple risk signals into a single prioritization score.
type CompositeScore struct {
	CapabilityScore float64 // Base capability score
	ReachabilityMod float64 // 1.0=unknown, 0.5=unreachable, 1.3=reachable
	CVEMod          float64 // 1.0 + 0.3 per HIGH CVE, capped at 2.0
	TaintMod        float64 // 1.0 + 0.25 per HIGH + 0.15 per MEDIUM taint
	Composite       float64 // Product of all modifiers, capped at 100
	Level           string  // Derived from Composite using standard thresholds (LOW, MEDIUM, HIGH)
}

// Compute calculates the composite score from capability set, reachability, CVE count, and taint findings.
//
// Parameters:
//   - caps: the capability set with its base score
//   - reachable: nil = unknown (mod 1.0), false = unreachable (mod 0.5), true = reachable (mod 1.3)
//   - cveCount: number of CVEs affecting the package/module
//   - taintFindings: taint findings for this package
//
// Returns:
//
//	CompositeScore with all modifiers and final composite value
func Compute(
	caps capability.CapabilitySet,
	reachable *bool,
	cveCount int,
	taintFindings []taint.TaintFinding,
) CompositeScore {
	score := CompositeScore{
		CapabilityScore: float64(caps.Score),
		ReachabilityMod: 1.0,
		CVEMod:          1.0,
		TaintMod:        1.0,
	}

	// Reachability modifier
	if reachable != nil {
		if *reachable {
			score.ReachabilityMod = 1.3
		} else {
			score.ReachabilityMod = 0.5
		}
	}

	// CVE modifier: +0.3 per HIGH CVE, capped at 2.0
	if cveCount > 0 {
		score.CVEMod = 1.0 + (float64(cveCount) * 0.3)
		if score.CVEMod > 2.0 {
			score.CVEMod = 2.0
		}
	}

	// Taint modifier: +0.25 per HIGH + 0.15 per MEDIUM
	for _, finding := range taintFindings {
		switch finding.Risk {
		case "HIGH":
			score.TaintMod += 0.25
		case "MEDIUM":
			score.TaintMod += 0.15
		}
	}

	// Composite = base × all modifiers, capped at 100
	score.Composite = score.CapabilityScore * score.ReachabilityMod * score.CVEMod * score.TaintMod
	if score.Composite > 100 {
		score.Composite = 100
	}

	// Derive risk level from composite score using standard thresholds
	score.Level = deriveLevel(score.Composite)

	return score
}

// deriveLevel maps composite score to risk level using standard thresholds.
func deriveLevel(composite float64) string {
	switch {
	case composite >= 30:
		return "HIGH"
	case composite >= 10:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
