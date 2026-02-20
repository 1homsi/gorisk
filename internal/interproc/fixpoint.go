package interproc

import (
	"fmt"
	"sort"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// ComputeFixpoint propagates summaries until convergence using a pending algorithm.
// It returns an error if the maximum number of iterations is exceeded.
func ComputeFixpoint(cg *ir.CSCallGraph, maxIterations int) error {
	Debugf("[fixpoint] Starting fixpoint computation with max %d iterations", maxIterations)

	// Initialize pending with all nodes in reverse topological order (leaves first).
	// Use a map for O(1) membership checks and a sorted slice for deterministic pops.
	order := TopologicalSort(cg)
	pending := make(map[string]bool, len(order))
	for _, node := range order {
		pending[node.String()] = true
	}

	// popWorklist returns the lexicographically-smallest pending key deterministically.
	popWorklist := func() (string, ir.ContextNode) {
		keys := make([]string, 0, len(pending))
		for k := range pending {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		key := keys[0]
		delete(pending, key)
		return key, cg.Nodes[key]
	}

	Infof("[fixpoint] Initialized pending with %d nodes", len(pending))
	iteration := 0

	for len(pending) > 0 && iteration < maxIterations {
		// Pop the smallest key for deterministic processing.
		nodeKey, node := popWorklist()

		Debugf("[fixpoint] Iteration %d: Processing %s (%d remaining in pending)",
			iteration, node.Function.String(), len(pending))

		// Handle SCC nodes specially
		if sccID, inSCC := cg.NodeToSCC[nodeKey]; inSCC {
			scc := cg.SCCs[sccID]
			summary := ComputeSCCSummary(scc, cg)

			// Update all nodes in the SCC with the collapsed summary
			for _, sccNode := range scc.Nodes {
				sccNodeKey := sccNode.String()
				oldSummary := cg.Summaries[sccNodeKey]

				if !SummariesEqual(oldSummary, summary) {
					summary.Node = sccNode // Update node reference
					summary.Iteration = iteration
					cg.Summaries[sccNodeKey] = summary

					// Re-enqueue callers of this node
					for _, caller := range cg.ReverseEdges[sccNodeKey] {
						// Don't re-enqueue nodes in the same SCC
						if callerSCCID, ok := cg.NodeToSCC[caller.String()]; !ok || callerSCCID != sccID {
							pending[caller.String()] = true
						}
					}
				}
			}

			iteration++
			continue
		}

		// Compute summary from direct capabilities and callee summaries
		summary := ComputeSummary(cg, node)
		summary.Iteration = iteration

		// Update if changed
		oldSummary := cg.Summaries[nodeKey]
		if !SummariesEqual(oldSummary, summary) {
			cg.Summaries[nodeKey] = summary

			// Log what changed
			if !summary.Transitive.IsEmpty() {
				Debugf("[fixpoint]   → Updated %s: transitive=%s, depth=%d, conf=%.2f",
					node.Function.String(), summary.Transitive.String(), summary.Depth, summary.Confidence)
			}

			// Re-enqueue all callers
			callers := cg.ReverseEdges[nodeKey]
			if len(callers) > 0 {
				Debugf("[fixpoint]   → Re-enqueuing %d callers", len(callers))
				for _, caller := range callers {
					Debugf("[fixpoint]     ← %s", caller.Function.String())
					pending[caller.String()] = true
				}
			}

			iteration++
		} else {
			Debugf("[fixpoint]   → No changes for %s (converged)", node.Function.String())
		}
	}

	if len(pending) > 0 {
		Errorf("[fixpoint] Did not converge after %d iterations (%d nodes remaining)", maxIterations, len(pending))
		return fmt.Errorf("fixpoint did not converge after %d iterations (%d nodes remaining)", maxIterations, len(pending))
	}

	Infof("[fixpoint] Converged in %d iterations", iteration)
	return nil
}

// ComputeSummary builds a summary from direct capabilities and callee summaries.
func ComputeSummary(cg *ir.CSCallGraph, node ir.ContextNode) ir.FunctionSummary {
	nodeKey := node.String()
	summary := ir.FunctionSummary{
		Node:       node,
		Confidence: 1.0,
	}

	// Start with existing direct capabilities (if any)
	existing := cg.Summaries[nodeKey]
	summary.Effects.MergeWithEvidence(existing.Effects)
	summary.Depth = 0

	// Classify direct capabilities into sources/sinks/sanitizers
	ClassifySummary(&summary)

	// Merge capabilities from callees with hop decay
	for _, callee := range cg.Edges[nodeKey] {
		calleeSummary := cg.Summaries[callee.String()]

		// Propagate transitive capabilities
		for _, cap := range calleeSummary.Effects.List() {
			// Apply hop multiplier to confidence
			newDepth := calleeSummary.Depth + 1
			if newDepth > 3 {
				continue // Stop propagating beyond 3 hops
			}

			multiplier := getHopMultiplier(newDepth)
			confidence := calleeSummary.Confidence * multiplier

			// Add to transitive set with decayed confidence
			ev := capability.CapabilityEvidence{
				Via:        "propagated",
				Confidence: confidence,
			}
			summary.Transitive.AddWithEvidence(cap, ev)

			// Update depth and confidence
			if newDepth > summary.Depth {
				summary.Depth = newDepth
			}
			if confidence < summary.Confidence {
				summary.Confidence = confidence
			}
		}

		// Also propagate callee's transitive capabilities
		for _, cap := range calleeSummary.Transitive.List() {
			newDepth := calleeSummary.Depth + 1
			if newDepth > 3 {
				continue
			}

			multiplier := getHopMultiplier(newDepth)
			confidence := calleeSummary.Confidence * multiplier

			ev := capability.CapabilityEvidence{
				Via:        "propagated",
				Confidence: confidence,
			}
			summary.Transitive.AddWithEvidence(cap, ev)

			if newDepth > summary.Depth {
				summary.Depth = newDepth
			}
			if confidence < summary.Confidence {
				summary.Confidence = confidence
			}
		}
	}

	return summary
}

// ComputeSCCSummary computes a summary for an entire SCC.
func ComputeSCCSummary(scc *ir.SCC, cg *ir.CSCallGraph) ir.FunctionSummary {
	// Start with collapsed summary
	summary := CollapseSCC(scc, cg)

	// Limit SCC iterations to 3 to prevent infinite loops
	if summary.Depth > 3 {
		summary.Depth = 3
	}

	return summary
}
