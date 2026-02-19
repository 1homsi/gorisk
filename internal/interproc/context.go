package interproc

import (
	"github.com/1homsi/gorisk/internal/ir"
)

// BuildCSCallGraph constructs a k-CFA call graph from an IRGraph.
// k=0: context-insensitive (all calls merge)
// k=1: caller-sensitive (distinguish by immediate caller)
// k>1: not yet implemented
func BuildCSCallGraph(irGraph ir.IRGraph, k int) *ir.CSCallGraph {
	Debugf("[context] Building k=%d call graph from IR (%d functions, %d edges)",
		k, len(irGraph.Functions), len(irGraph.Calls))

	cg := &ir.CSCallGraph{
		Nodes:        make(map[string]ir.ContextNode),
		Edges:        make(map[string][]ir.ContextNode),
		ReverseEdges: make(map[string][]ir.ContextNode),
		Summaries:    make(map[string]ir.FunctionSummary),
		SCCs:         make(map[int]*ir.SCC),
		NodeToSCC:    make(map[string]int),
	}

	// Build caller → callees map for BFS traversal
	callerToCallees := make(map[string][]ir.CallEdge)
	for _, edge := range irGraph.Calls {
		callerKey := edge.Caller.String()
		callerToCallees[callerKey] = append(callerToCallees[callerKey], edge)
	}

	// BFS from all entry points (functions with no callers or explicit entry functions)
	entryFunctions := findEntryFunctions(irGraph, callerToCallees)
	Debugf("[context] Found %d entry functions", len(entryFunctions))

	// Worklist: (function, context)
	type workItem struct {
		function ir.Symbol
		context  ir.Context
	}

	worklist := make([]workItem, 0, len(entryFunctions))
	for _, fn := range entryFunctions {
		worklist = append(worklist, workItem{
			function: fn,
			context:  ir.Context{}, // Empty context for entry points
		})
	}

	visited := make(map[string]bool)
	nodeCount := 0

	for len(worklist) > 0 {
		// Pop from worklist
		item := worklist[0]
		worklist = worklist[1:]

		// Create context node
		node := ir.ContextNode{
			Function: item.function,
			Context:  item.context,
		}
		nodeKey := node.String()

		// Skip if already visited
		if visited[nodeKey] {
			continue
		}
		visited[nodeKey] = true
		nodeCount++

		// Add to graph
		cg.Nodes[nodeKey] = node

		// Initialize summary with direct capabilities
		funcCaps, ok := irGraph.Functions[item.function.String()]
		if ok {
			summary := ir.FunctionSummary{
				Node:       node,
				Confidence: 1.0,
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

			// Add edge
			cg.Edges[nodeKey] = append(cg.Edges[nodeKey], calleeNode)
			cg.ReverseEdges[calleeKey] = append(cg.ReverseEdges[calleeKey], node)

			// Enqueue callee if not visited
			if !visited[calleeKey] {
				worklist = append(worklist, workItem{
					function: edge.Callee,
					context:  newContext,
				})
			}
		}
	}

	Infof("[context] Built call graph: %d nodes, %d edges", nodeCount, len(cg.Edges))
	return cg
}

// findEntryFunctions identifies functions that should be entry points.
func findEntryFunctions(irGraph ir.IRGraph, callerToCallees map[string][]ir.CallEdge) []ir.Symbol {
	// Find all functions that are callees
	isCallee := make(map[string]bool)
	for _, edges := range callerToCallees {
		for _, edge := range edges {
			isCallee[edge.Callee.String()] = true
		}
	}

	// Entry functions are those that are never called (or explicitly marked)
	var entries []ir.Symbol
	for fnKey, funcCaps := range irGraph.Functions {
		// If this function has callees but is not itself a callee, it's an entry
		if len(callerToCallees[fnKey]) > 0 && !isCallee[fnKey] {
			entries = append(entries, funcCaps.Symbol)
			continue
		}

		// Also include functions named "main" or "init"
		if funcCaps.Symbol.Name == "main" || funcCaps.Symbol.Name == "init" {
			entries = append(entries, funcCaps.Symbol)
		}
	}

	// If no entries found, include all functions (for libraries)
	if len(entries) == 0 {
		for _, funcCaps := range irGraph.Functions {
			entries = append(entries, funcCaps.Symbol)
		}
	}

	return entries
}

// ConsolidateIR converts package-level IR into a unified IRGraph.
func ConsolidateIR(pkgCaps map[string]map[string]ir.FunctionCaps, pkgEdges map[string][]ir.CallEdge) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	// Merge all functions
	for _, funcMap := range pkgCaps {
		for fnKey, funcCaps := range funcMap {
			irGraph.Functions[fnKey] = funcCaps
		}
	}

	// Merge all call edges
	for _, edges := range pkgEdges {
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	return irGraph
}
