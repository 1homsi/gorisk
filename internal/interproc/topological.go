package interproc

import (
	"sort"

	"github.com/1homsi/gorisk/internal/ir"
)

// TopologicalSort returns nodes in reverse topological order (leaves first).
// This ordering ensures that we process callees before callers in the fixpoint algorithm.
// Nodes in cycles will be ordered arbitrarily within their SCC.
func TopologicalSort(cg *ir.CSCallGraph) []ir.ContextNode {
	var (
		visited = make(map[string]bool)
		result  []ir.ContextNode
	)

	var visit func(ir.ContextNode)
	visit = func(node ir.ContextNode) {
		nodeKey := node.String()
		if visited[nodeKey] {
			return
		}
		visited[nodeKey] = true

		// Visit all callees first (DFS post-order)
		callees := cg.Edges[nodeKey]
		// Sort callees for determinism
		sortedCallees := make([]ir.ContextNode, len(callees))
		copy(sortedCallees, callees)
		sort.Slice(sortedCallees, func(i, j int) bool {
			return sortedCallees[i].String() < sortedCallees[j].String()
		})

		for _, callee := range sortedCallees {
			visit(callee)
		}

		// Add this node after all its callees
		result = append(result, node)
	}

	// Sort nodes for deterministic iteration
	nodes := make([]ir.ContextNode, 0, len(cg.Nodes))
	for _, node := range cg.Nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].String() < nodes[j].String()
	})

	// Visit all nodes
	for _, node := range nodes {
		visit(node)
	}

	return result
}

// ReverseTopologicalSort returns nodes in topological order (roots first).
// This is useful for forward dataflow analysis.
func ReverseTopologicalSort(cg *ir.CSCallGraph) []ir.ContextNode {
	order := TopologicalSort(cg)

	// Reverse the slice
	for i := 0; i < len(order)/2; i++ {
		j := len(order) - 1 - i
		order[i], order[j] = order[j], order[i]
	}

	return order
}

// GetRoots returns all entry point nodes (nodes with no callers).
func GetRoots(cg *ir.CSCallGraph) []ir.ContextNode {
	var roots []ir.ContextNode

	for nodeKey, node := range cg.Nodes {
		// A node is a root if it has no callers
		if len(cg.ReverseEdges[nodeKey]) == 0 {
			roots = append(roots, node)
		}
	}

	// Sort for determinism
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].String() < roots[j].String()
	})

	return roots
}

// GetLeaves returns all leaf nodes (nodes with no callees).
func GetLeaves(cg *ir.CSCallGraph) []ir.ContextNode {
	var leaves []ir.ContextNode

	for nodeKey, node := range cg.Nodes {
		// A node is a leaf if it has no callees
		if len(cg.Edges[nodeKey]) == 0 {
			leaves = append(leaves, node)
		}
	}

	// Sort for determinism
	sort.Slice(leaves, func(i, j int) bool {
		return leaves[i].String() < leaves[j].String()
	})

	return leaves
}
