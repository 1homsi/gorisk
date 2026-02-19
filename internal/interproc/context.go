package interproc

import (
	"sort"

	"github.com/1homsi/gorisk/internal/ir"
)

// BuildCSCallGraph constructs a k-CFA call graph from a base IRGraph.
// For k=1, context is the immediate caller. For k=0, all contexts are merged.
func BuildCSCallGraph(irGraph ir.IRGraph, k int) *ir.CSCallGraph {
	Debugf("[context] Building k=%d CFA call graph from %d functions", k, len(irGraph.Functions))
	cg := ir.NewCSCallGraph()

	// Build a map of caller → callees from IRGraph
	callerToCallees := make(map[string][]ir.CallEdge)
	for _, edge := range irGraph.Calls {
		caller := edge.Caller.String()
		callerToCallees[caller] = append(callerToCallees[caller], edge)
	}

	// Find entry points (functions with no callers)
	allCallees := make(map[string]bool)
	for _, edges := range callerToCallees {
		for _, edge := range edges {
			allCallees[edge.Callee.String()] = true
		}
	}

	var entryPoints []ir.Symbol
	for funcKey, funcCaps := range irGraph.Functions {
		// Entry point if it's not called by anyone, or if it's a common entry like main/init
		isEntry := !allCallees[funcKey]
		isMain := funcCaps.Symbol.Name == "main" || funcCaps.Symbol.Name == "init"

		if isEntry || isMain {
			entryPoints = append(entryPoints, funcCaps.Symbol)
		}
	}

	// Sort entry points for determinism
	sort.Slice(entryPoints, func(i, j int) bool {
		return entryPoints[i].String() < entryPoints[j].String()
	})

	// If no entry points found, use all functions
	if len(entryPoints) == 0 {
		for _, funcCaps := range irGraph.Functions {
			entryPoints = append(entryPoints, funcCaps.Symbol)
		}
		sort.Slice(entryPoints, func(i, j int) bool {
			return entryPoints[i].String() < entryPoints[j].String()
		})
	}

	// BFS traversal with context tracking
	type workItem struct {
		function ir.Symbol
		context  ir.Context
	}

	queue := make([]workItem, 0)
	visited := make(map[string]bool)

	// Initialize queue with entry points (empty context)
	for _, entry := range entryPoints {
		queue = append(queue, workItem{
			function: entry,
			context:  ir.Context{}, // Empty context for entry points
		})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Create context node
		node := ir.ContextNode{
			Function: item.function,
			Context:  item.context,
		}
		nodeKey := node.String()

		// Skip if already visited (for k=0 or when same context is reached)
		if visited[nodeKey] {
			continue
		}
		visited[nodeKey] = true

		// Add node to call graph
		cg.Nodes[nodeKey] = node

		// Initialize summary with direct capabilities from IRGraph
		if funcCaps, ok := irGraph.Functions[item.function.String()]; ok {
			summary := ir.FunctionSummary{
				Node:       node,
				Confidence: 1.0,
				Depth:      0,
			}
			summary.Effects.MergeWithEvidence(funcCaps.DirectCaps)
			ClassifySummary(&summary)
			cg.Summaries[nodeKey] = summary
		}

		// Process callees
		for _, edge := range callerToCallees[item.function.String()] {
			// Determine new context based on k
			var newContext ir.Context
			switch k {
			case 0:
				// k=0: context-insensitive, always empty context
				newContext = ir.Context{}
			case 1:
				// k=1: context is the immediate caller
				newContext = ir.Context{Caller: item.function}
			default:
				// k>1: not implemented yet, fall back to k=1
				newContext = ir.Context{Caller: item.function}
			}

			calleeNode := ir.ContextNode{
				Function: edge.Callee,
				Context:  newContext,
			}
			calleeKey := calleeNode.String()

			// Add edge: node → calleeNode
			cg.Edges[nodeKey] = append(cg.Edges[nodeKey], calleeNode)

			// Add reverse edge: calleeNode → node
			cg.ReverseEdges[calleeKey] = append(cg.ReverseEdges[calleeKey], node)

			// Enqueue callee if not visited
			if !visited[calleeKey] {
				queue = append(queue, workItem{
					function: edge.Callee,
					context:  newContext,
				})
			}
		}
	}

	Infof("[context] Built call graph: %d context-sensitive nodes, %d edges", len(cg.Nodes), countEdges(cg))
	return cg
}

// countEdges counts total edges in the call graph
func countEdges(cg *ir.CSCallGraph) int {
	total := 0
	for _, edges := range cg.Edges {
		total += len(edges)
	}
	return total
}

// ConsolidateIR builds an IRGraph from package-level capabilities and call edges.
// This is a helper for existing code that uses per-package FunctionCaps maps.
func ConsolidateIR(pkgCaps map[string]map[string]ir.FunctionCaps, pkgEdges map[string][]ir.CallEdge) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
	}

	// Collect all function capabilities
	for _, funcMap := range pkgCaps {
		for funcKey, funcCaps := range funcMap {
			irGraph.Functions[funcKey] = funcCaps
		}
	}

	// Collect all call edges
	for _, edges := range pkgEdges {
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
