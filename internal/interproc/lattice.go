package interproc

import (
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// Hop multipliers for confidence decay based on call depth
var hopMultipliers = map[int]float64{
	0: 1.0,  // Direct capability
	1: 0.70, // One hop
	2: 0.55, // Two hops
	3: 0.40, // Three or more hops
}

// getHopMultiplier returns the confidence multiplier for a given hop count.
func getHopMultiplier(hops int) float64 {
	if m, ok := hopMultipliers[hops]; ok {
		return m
	}
	return hopMultipliers[3] // Use 3+ multiplier for anything beyond
}

// JoinSummaries combines two function summaries using lattice join operations.
// This implements the monotonic merge required for fixpoint convergence.
func JoinSummaries(a, b ir.FunctionSummary) ir.FunctionSummary {
	result := ir.FunctionSummary{
		Node: a.Node, // Keep the node from the first summary
	}

	// Union of all capability sets
	result.Sources.MergeWithEvidence(a.Sources)
	result.Sources.MergeWithEvidence(b.Sources)

	result.Sinks.MergeWithEvidence(a.Sinks)
	result.Sinks.MergeWithEvidence(b.Sinks)

	result.Sanitizers.MergeWithEvidence(a.Sanitizers)
	result.Sanitizers.MergeWithEvidence(b.Sanitizers)

	result.Effects.MergeWithEvidence(a.Effects)
	result.Effects.MergeWithEvidence(b.Effects)

	result.Transitive.MergeWithEvidence(a.Transitive)
	result.Transitive.MergeWithEvidence(b.Transitive)

	// Maximum depth
	if a.Depth > b.Depth {
		result.Depth = a.Depth
	} else {
		result.Depth = b.Depth
	}

	// Minimum confidence (most conservative)
	if a.Confidence > 0 && b.Confidence > 0 {
		if a.Confidence < b.Confidence {
			result.Confidence = a.Confidence
		} else {
			result.Confidence = b.Confidence
		}
	} else if a.Confidence > 0 {
		result.Confidence = a.Confidence
	} else {
		result.Confidence = b.Confidence
	}

	// Combine call stacks
	result.CallStack = append(append([]ir.CallEdge{}, a.CallStack...), b.CallStack...)

	// Maximum iteration
	if a.Iteration > b.Iteration {
		result.Iteration = a.Iteration
	} else {
		result.Iteration = b.Iteration
	}

	return result
}

// SummariesEqual checks if two summaries are equivalent for convergence detection.
func SummariesEqual(a, b ir.FunctionSummary) bool {
	// Check if capability sets are equal
	if !capSetsEqual(a.Sources, b.Sources) {
		return false
	}
	if !capSetsEqual(a.Sinks, b.Sinks) {
		return false
	}
	if !capSetsEqual(a.Sanitizers, b.Sanitizers) {
		return false
	}
	if !capSetsEqual(a.Effects, b.Effects) {
		return false
	}
	if !capSetsEqual(a.Transitive, b.Transitive) {
		return false
	}

	// Check depth and confidence
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

	for i := range aList {
		if aList[i] != bList[i] {
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

// ClassifySummary populates the Sources, Sinks, and Sanitizers sets based on Effects.
func ClassifySummary(summary *ir.FunctionSummary) {
	for _, cap := range summary.Effects.List() {
		role := capability.ClassifyCapability(cap)
		switch role {
		case capability.RoleSource:
			if evs, ok := summary.Effects.Evidence[cap]; ok {
				for _, ev := range evs {
					summary.Sources.AddWithEvidence(cap, ev)
				}
			} else {
				summary.Sources.Add(cap)
			}
		case capability.RoleSink:
			if evs, ok := summary.Effects.Evidence[cap]; ok {
				for _, ev := range evs {
					summary.Sinks.AddWithEvidence(cap, ev)
				}
			} else {
				summary.Sinks.Add(cap)
			}
		case capability.RoleSanitizer:
			if evs, ok := summary.Effects.Evidence[cap]; ok {
				for _, ev := range evs {
					summary.Sanitizers.AddWithEvidence(cap, ev)
				}
			} else {
				summary.Sanitizers.Add(cap)
			}
		}
	}
}
