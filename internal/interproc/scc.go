package interproc

import (
	"github.com/1homsi/gorisk/internal/ir"
)

// sccState holds Tarjan's algorithm state for a single node.
type sccState struct {
	index   int
	lowlink int
	onStack bool
}

// DetectSCCs finds strongly connected components using Tarjan's algorithm.
// It populates cg.SCCs and cg.NodeToSCC.
func DetectSCCs(cg *ir.CSCallGraph) {
	Debugf("[scc] Starting SCC detection on %d nodes", len(cg.Nodes))

	var (
		index     = 0
		stack     []ir.ContextNode
		state     = make(map[string]*sccState)
		sccID     = 0
		sccs      = make(map[int]*ir.SCC)
		nodeToSCC = make(map[string]int)
	)

	var strongConnect func(ir.ContextNode)
	strongConnect = func(v ir.ContextNode) {
		vKey := v.String()

		// Set the depth index for v to the smallest unused index
		state[vKey] = &sccState{
			index:   index,
			lowlink: index,
			onStack: true,
		}
		index++
		stack = append(stack, v)

		// Consider successors of v
		for _, w := range cg.Edges[vKey] {
			wKey := w.String()
			wState := state[wKey]

			if wState == nil {
				// Successor w has not yet been visited; recurse on it
				strongConnect(w)
				if state[wKey].lowlink < state[vKey].lowlink {
					state[vKey].lowlink = state[wKey].lowlink
				}
			} else if wState.onStack {
				// Successor w is in stack S and hence in the current SCC
				if wState.index < state[vKey].lowlink {
					state[vKey].lowlink = wState.index
				}
			}
		}

		// If v is a root node, pop the stack and create an SCC
		if state[vKey].lowlink == state[vKey].index {
			var sccNodes []ir.ContextNode
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				state[w.String()].onStack = false
				sccNodes = append(sccNodes, w)
				if w.String() == vKey {
					break
				}
			}

			// Only create SCC if it contains more than one node or a self-loop
			if len(sccNodes) > 1 || hasSelfLoop(cg, sccNodes[0]) {
				scc := &ir.SCC{
					ID:    sccID,
					Nodes: sccNodes,
				}
				sccs[sccID] = scc
				for _, node := range sccNodes {
					nodeToSCC[node.String()] = sccID
				}
				Debugf("[scc] Found SCC #%d with %d nodes", sccID, len(sccNodes))
				if Verbose && len(sccNodes) <= 5 {
					for _, n := range sccNodes {
						Debugf("[scc]   - %s", n.Function.String())
					}
				}
				sccID++
			}
		}
	}

	// Run Tarjan's algorithm from each unvisited node
	for nodeKey := range cg.Nodes {
		if state[nodeKey] == nil {
			strongConnect(cg.Nodes[nodeKey])
		}
	}

	cg.SCCs = sccs
	cg.NodeToSCC = nodeToSCC

	totalNodesInSCCs := 0
	for _, scc := range sccs {
		totalNodesInSCCs += len(scc.Nodes)
	}
	Infof("[scc] Detected %d SCCs containing %d nodes total", len(sccs), totalNodesInSCCs)
}

// hasSelfLoop checks if a node has an edge to itself.
func hasSelfLoop(cg *ir.CSCallGraph, node ir.ContextNode) bool {
	nodeKey := node.String()
	for _, callee := range cg.Edges[nodeKey] {
		if callee.String() == nodeKey {
			return true
		}
	}
	return false
}

// CollapseSCC creates a unified summary for an SCC by joining all node summaries.
// It limits recursion depth to 3 iterations within the SCC to prevent infinite loops.
func CollapseSCC(scc *ir.SCC, cg *ir.CSCallGraph) ir.FunctionSummary {
	if len(scc.Nodes) == 0 {
		return ir.FunctionSummary{}
	}

	// Initialize with the first node as a representative
	collapsed := ir.FunctionSummary{
		Node:       scc.Nodes[0],
		Confidence: 1.0,
	}

	// Join all summaries in the SCC
	for _, node := range scc.Nodes {
		summary := cg.Summaries[node.String()]

		// Merge capabilities
		collapsed.Sources.MergeWithEvidence(summary.Sources)
		collapsed.Sinks.MergeWithEvidence(summary.Sinks)
		collapsed.Sanitizers.MergeWithEvidence(summary.Sanitizers)
		collapsed.Effects.MergeWithEvidence(summary.Effects)
		collapsed.Transitive.MergeWithEvidence(summary.Transitive)

		// Take maximum depth (most conservative)
		if summary.Depth > collapsed.Depth {
			collapsed.Depth = summary.Depth
		}

		// Take minimum confidence (most conservative)
		if summary.Confidence > 0 && (collapsed.Confidence == 0 || summary.Confidence < collapsed.Confidence) {
			collapsed.Confidence = summary.Confidence
		}

		// Accumulate call stacks
		collapsed.CallStack = append(collapsed.CallStack, summary.CallStack...)
	}

	// Limit depth to 3 for SCC nodes (prevents infinite recursion)
	if collapsed.Depth > 3 {
		collapsed.Depth = 3
	}

	return collapsed
}
