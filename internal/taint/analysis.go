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

// traceTaintFlow finds the call path from source to sink.
func (ta *TaintAnalysis) traceTaintFlow(node ir.ContextNode, source, sink capability.Capability) *TaintFlow {
	// Simple heuristic: find where source and sink are directly present
	summary := ta.CallGraph.Summaries[node.String()]

	// Check if this node directly has both
	directSource := summary.Sources.Has(source)
	directSink := summary.Sinks.Has(sink)

	if directSource && directSink {
		// Both in same function
		return &TaintFlow{
			SourceFunction: node.Function,
			SinkFunction:   node.Function,
			CallPath:       []ir.CallEdge{},
			Sanitized:      summary.Sanitizers.Has(capability.CapCrypto),
		}
	}

	// Otherwise, try to find source in callees and sink locally, or vice versa
	// This is a simplified version; a full implementation would use BFS/DFS

	// Check if source is in a callee and sink is local
	if directSink {
		for _, callee := range ta.CallGraph.Edges[node.String()] {
			calleeSummary := ta.CallGraph.Summaries[callee.String()]
			if calleeSummary.Sources.Has(source) || calleeSummary.Transitive.Has(source) {
				return &TaintFlow{
					SourceFunction: callee.Function,
					SinkFunction:   node.Function,
					CallPath: []ir.CallEdge{
						{Caller: node.Function, Callee: callee.Function},
					},
					Sanitized: summary.Sanitizers.Has(capability.CapCrypto) || calleeSummary.Sanitizers.Has(capability.CapCrypto),
				}
			}
		}
	}

	// Check if sink is in a callee and source is local
	if directSource {
		for _, callee := range ta.CallGraph.Edges[node.String()] {
			calleeSummary := ta.CallGraph.Summaries[callee.String()]
			if calleeSummary.Sinks.Has(sink) || calleeSummary.Transitive.Has(sink) {
				return &TaintFlow{
					SourceFunction: node.Function,
					SinkFunction:   callee.Function,
					CallPath: []ir.CallEdge{
						{Caller: node.Function, Callee: callee.Function},
					},
					Sanitized: summary.Sanitizers.Has(capability.CapCrypto) || calleeSummary.Sanitizers.Has(capability.CapCrypto),
				}
			}
		}
	}

	// If we reach here, the flow is more complex (multi-hop)
	// For now, return a simple flow
	return &TaintFlow{
		SourceFunction: node.Function,
		SinkFunction:   node.Function,
		CallPath:       []ir.CallEdge{},
		Sanitized:      summary.Sanitizers.Has(capability.CapCrypto),
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
