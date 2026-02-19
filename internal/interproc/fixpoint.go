package interproc

import (
	"fmt"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// ComputeFixpoint propagates summaries until convergence using a worklist algorithm.
// It returns an error if the maximum number of iterations is exceeded.
func ComputeFixpoint(cg *ir.CSCallGraph, maxIterations int) error {
	Debugf("[fixpoint] Starting fixpoint computation with max %d iterations", maxIterations)

	// Initialize worklist with all nodes in reverse topological order (leaves first)
	order := TopologicalSort(cg)
	worklist := make(map[string]bool)
	for _, node := range order {
		worklist[node.String()] = true
	}

	Infof("[fixpoint] Initialized worklist with %d nodes", len(worklist))
	iteration := 0

	for len(worklist) > 0 && iteration < maxIterations {
		// Pop a node from the worklist (deterministic order)
		var node ir.ContextNode
		var nodeKey string
		for k := range worklist {
			nodeKey = k
			node = cg.Nodes[k]
			break
		}
		delete(worklist, nodeKey)

		Debugf("[fixpoint] Iteration %d: Processing %s (%d remaining in worklist)",
			iteration, node.Function.String(), len(worklist))

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
							worklist[caller.String()] = true
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
					worklist[caller.String()] = true
				}
			}

			iteration++
		} else {
			Debugf("[fixpoint]   → No changes for %s (converged)", node.Function.String())
		}
	}

	if len(worklist) > 0 {
		Errorf("[fixpoint] Did not converge after %d iterations (%d nodes remaining)", maxIterations, len(worklist))
		return fmt.Errorf("fixpoint did not converge after %d iterations (%d nodes remaining)", maxIterations, len(worklist))
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
