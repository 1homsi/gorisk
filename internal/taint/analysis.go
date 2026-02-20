package taint

import (
	"log"
	"os"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

var (
	// Verbose controls taint analysis logging
	Verbose = os.Getenv("GORISK_VERBOSE") == "1"
	logger  = log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds)
)

// SetVerbose enables or disables verbose taint logging
func SetVerbose(enabled bool) {
	Verbose = enabled
}

func debugf(format string, args ...interface{}) {
	if Verbose {
		logger.Printf("[DEBUG] [taint] "+format, args...)
	}
}

func infof(format string, args ...interface{}) {
	if Verbose {
		logger.Printf("[INFO] [taint] "+format, args...)
	}
}

// TaintAnalysis performs interprocedural taint analysis on a call graph.
type TaintAnalysis struct {
	CallGraph *ir.CSCallGraph
	Rules     []taintRule
}

// NewInterprocedural creates a new interprocedural taint analyzer.
func NewInterprocedural(cg *ir.CSCallGraph) *TaintAnalysis {
	return &TaintAnalysis{
		CallGraph: cg,
		Rules:     taintRules,
	}
}

// AnalyzeInterprocedural finds source→sink flows across function boundaries.
// It returns findings with call stacks showing the flow path.
func (ta *TaintAnalysis) AnalyzeInterprocedural() []TaintFinding {
	var findings []TaintFinding

	// Import interproc for logging
	// For each node in the call graph, check if both source and sink are reachable
	for nodeKey, node := range ta.CallGraph.Nodes {
		summary := ta.CallGraph.Summaries[nodeKey]

		// Check each taint rule
		for _, rule := range ta.Rules {
			// Check if this node or its transitive dependencies have both source and sink
			hasSource := summary.Sources.Has(rule.Source) || summary.Transitive.Has(rule.Source)
			hasSink := summary.Sinks.Has(rule.Sink) || summary.Transitive.Has(rule.Sink)

			if hasSource && hasSink {
				// Find the actual flow path
				flow := ta.traceTaintFlow(node, rule.Source, rule.Sink)

				if flow != nil {
					// Compute confidence
					sourceConf := ta.getConfidence(summary, rule.Source)
					sinkConf := ta.getConfidence(summary, rule.Sink)
					conf := min(sourceConf, sinkConf)

					// Downgrade severity if low confidence
					risk := rule.Risk
					if conf > 0 && conf < 0.70 {
						risk = downgradeSeverity(risk)
					}

					// Extract package name from node
					pkg := node.Function.Package
					if pkg == "" {
						pkg = "." // Local package
					}

					finding := TaintFinding{
						Package:    pkg,
						Source:     rule.Source,
						Sink:       rule.Sink,
						Risk:       risk,
						Note:       rule.Note,
						Confidence: conf,
						EvidenceChain: []TaintEvidence{
							{Capability: rule.Source, Confidence: sourceConf},
							{Capability: rule.Sink, Confidence: sinkConf},
						},
						SourceFunc: flow.SourceFunction.String(),
						SinkFunc:   flow.SinkFunction.String(),
						CallStack:  ta.formatCallStack(flow.CallPath),
					}

					// Log the taint flow discovery
					infof("Found %s flow: %s → %s in %s (confidence: %.2f)",
						risk, rule.Source, rule.Sink, pkg, conf)
					debugf("  Source: %s", flow.SourceFunction.String())
					debugf("  Sink: %s", flow.SinkFunction.String())
					if len(flow.CallPath) > 0 {
						debugf("  Call path: %d hops", len(flow.CallPath))
						for i, edge := range flow.CallPath {
							debugf("    %d. %s → %s", i+1, edge.Caller.String(), edge.Callee.String())
						}
					}

					findings = append(findings, finding)
				}
			}
		}
	}

	// Sort findings by risk level
	sortFindings(findings)

	// Deduplicate findings (same package + source + sink)
	findings = deduplicateFindings(findings)

	return findings
}

// TaintFlow represents a source→sink path through the call graph.
type TaintFlow struct {
	SourceFunction ir.Symbol
	SinkFunction   ir.Symbol
	CallPath       []ir.CallEdge
	Sanitized      bool // crypto/validation in path
}

// traceTaintFlow finds the multi-hop call path from a source-carrying node to
// a sink-carrying node using BFS over the call graph edges.
//
// The startNode is a node that AnalyzeInterprocedural already determined has
// both the source and sink capabilities (directly or transitively). traceTaintFlow
// walks forward from startNode to find the actual function where the sink occurs,
// producing a concrete call path for explanations.
func (ta *TaintAnalysis) traceTaintFlow(startNode ir.ContextNode, source, sink capability.Capability) *TaintFlow {
	startSummary := ta.CallGraph.Summaries[startNode.String()]
	startSanitized := startSummary.Sanitizers.Has(capability.CapCrypto)

	// If both source and sink are directly in the same function, the path is empty.
	directSrc := startSummary.Sources.Has(source) || startSummary.Effects.Has(source)
	directSink := startSummary.Sinks.Has(sink) || startSummary.Effects.Has(sink)
	if directSrc && directSink {
		return &TaintFlow{
			SourceFunction: startNode.Function,
			SinkFunction:   startNode.Function,
			CallPath:       []ir.CallEdge{},
			Sanitized:      startSanitized,
		}
	}

	// BFS: from startNode (which has source, directly or transitively), walk
	// forward through call edges to find the first node that directly has sink.
	type bfsItem struct {
		node ir.ContextNode
		path []ir.CallEdge
	}

	queue := []bfsItem{{node: startNode, path: nil}}
	visited := make(map[string]bool)

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		key := item.node.String()
		if visited[key] {
			continue
		}
		visited[key] = true

		summary := ta.CallGraph.Summaries[key]
		nodeHasSink := summary.Sinks.Has(sink) || summary.Effects.Has(sink)

		// If we've moved away from the start and found a node with sink, report the path.
		if len(item.path) > 0 && nodeHasSink {
			sanitized := startSanitized || summary.Sanitizers.Has(capability.CapCrypto)
			srcFunc := startNode.Function
			if len(item.path) > 0 {
				srcFunc = item.path[0].Caller
			}
			return &TaintFlow{
				SourceFunction: srcFunc,
				SinkFunction:   item.node.Function,
				CallPath:       item.path,
				Sanitized:      sanitized,
			}
		}

		// Extend BFS to callees.
		for _, callee := range ta.CallGraph.Edges[key] {
			if visited[callee.String()] {
				continue
			}
			newPath := make([]ir.CallEdge, len(item.path)+1)
			copy(newPath, item.path)
			newPath[len(item.path)] = ir.CallEdge{
				Caller: item.node.Function,
				Callee: callee.Function,
			}
			queue = append(queue, bfsItem{node: callee, path: newPath})
		}
	}

	// Fallback: return a minimal flow anchored at the start node.
	return &TaintFlow{
		SourceFunction: startNode.Function,
		SinkFunction:   startNode.Function,
		CallPath:       []ir.CallEdge{},
		Sanitized:      startSanitized,
	}
}

// getConfidence returns the confidence for a capability in a summary.
func (ta *TaintAnalysis) getConfidence(summary ir.FunctionSummary, cap capability.Capability) float64 {
	// Check direct effects first
	if conf := summary.Effects.Confidence(cap); conf > 0 {
		return conf
	}

	// Check sources
	if conf := summary.Sources.Confidence(cap); conf > 0 {
		return conf
	}

	// Check sinks
	if conf := summary.Sinks.Confidence(cap); conf > 0 {
		return conf
	}

	// Check transitive
	if conf := summary.Transitive.Confidence(cap); conf > 0 {
		return conf
	}

	// Default
	return summary.Confidence
}

// formatCallStack formats a call path as a list of function names.
func (ta *TaintAnalysis) formatCallStack(path []ir.CallEdge) []string {
	if len(path) == 0 {
		return nil
	}

	stack := make([]string, 0, len(path)+1)
	if len(path) > 0 {
		stack = append(stack, path[0].Caller.String())
	}

	for _, edge := range path {
		stack = append(stack, edge.Callee.String())
	}

	return stack
}

// deduplicateFindings removes duplicate findings (same package + source + sink).
func deduplicateFindings(findings []TaintFinding) []TaintFinding {
	seen := make(map[string]bool)
	result := make([]TaintFinding, 0, len(findings))

	for _, f := range findings {
		key := f.Package + "|" + f.Source + "|" + f.Sink
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}
