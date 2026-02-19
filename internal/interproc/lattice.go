package interproc

import (
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// ClassifySummary categorizes capabilities into sources, sinks, and sanitizers.
func ClassifySummary(summary *ir.FunctionSummary) {
	for _, cap := range summary.Effects.List() {
		role := capability.ClassifyCapability(cap)

		// Get evidence for this capability (use first evidence if available)
		var evidence capability.CapabilityEvidence
		if evs := summary.Effects.Evidence[cap]; len(evs) > 0 {
			evidence = evs[0]
		}

		switch role {
		case capability.RoleSource:
			summary.Sources.AddWithEvidence(cap, evidence)
		case capability.RoleSink:
			summary.Sinks.AddWithEvidence(cap, evidence)
		case capability.RoleSanitizer:
			summary.Sanitizers.AddWithEvidence(cap, evidence)
		}
	}
}

// getHopMultiplier returns the confidence multiplier for a given hop depth.
// Hop 0 (direct): 1.00
// Hop 1: 0.70
// Hop 2: 0.55
// Hop 3+: 0.40
func getHopMultiplier(depth int) float64 {
	switch depth {
	case 0:
		return 1.00
	case 1:
		return 0.70
	case 2:
		return 0.55
	default: // 3+
		return 0.40
	}
}

// JoinSummaries merges two summaries (for SCC collapse or merging contexts).
func JoinSummaries(a, b ir.FunctionSummary) ir.FunctionSummary {
	result := ir.FunctionSummary{
		Node: a.Node, // Use first node as representative
	}

	// Merge capability sets
	result.Effects.MergeWithEvidence(a.Effects)
	result.Effects.MergeWithEvidence(b.Effects)

	result.Sources.MergeWithEvidence(a.Sources)
	result.Sources.MergeWithEvidence(b.Sources)

	result.Sinks.MergeWithEvidence(a.Sinks)
	result.Sinks.MergeWithEvidence(b.Sinks)

	result.Sanitizers.MergeWithEvidence(a.Sanitizers)
	result.Sanitizers.MergeWithEvidence(b.Sanitizers)

	result.Transitive.MergeWithEvidence(a.Transitive)
	result.Transitive.MergeWithEvidence(b.Transitive)

	// Take maximum depth
	if a.Depth > b.Depth {
		result.Depth = a.Depth
	} else {
		result.Depth = b.Depth
	}

	// Take minimum confidence (conservative)
	if a.Confidence < b.Confidence {
		result.Confidence = a.Confidence
	} else {
		result.Confidence = b.Confidence
	}

	return result
}

// SummariesEqual checks if two summaries are equivalent (for fixpoint convergence).
func SummariesEqual(a, b ir.FunctionSummary) bool {
	// Check capability sets
	if !capSetsEqual(a.Effects, b.Effects) {
		return false
	}
	if !capSetsEqual(a.Sources, b.Sources) {
		return false
	}
	if !capSetsEqual(a.Sinks, b.Sinks) {
		return false
	}
	if !capSetsEqual(a.Sanitizers, b.Sanitizers) {
		return false
	}
	if !capSetsEqual(a.Transitive, b.Transitive) {
		return false
	}

	// Check depth
	if a.Depth != b.Depth {
		return false
	}

	// Allow small floating point differences in confidence
	const epsilon = 0.001
	return abs(a.Confidence-b.Confidence) <= epsilon
}

// capSetsEqual checks if two capability sets contain the same capabilities.
func capSetsEqual(a, b capability.CapabilitySet) bool {
	aList := a.List()
	bList := b.List()

	if len(aList) != len(bList) {
		return false
	}

	// Check each capability exists in both sets
	for _, cap := range aList {
		if !b.Has(cap) {
			return false
		}
	}

	return true
}

// abs returns the absolute value of a float64.
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
