package ir

import "github.com/1homsi/gorisk/internal/capability"

// Symbol identifies a named code entity.
type Symbol struct {
	Package string // fully-qualified import path ("" = current package)
	Name    string // function / method / var / type name
	Kind    string // "func" | "method" | "var" | "type"
}

// String returns "Package.Name", or ".Name" when Package is empty.
func (s Symbol) String() string {
	if s.Package == "" {
		return "." + s.Name
	}
	return s.Package + "." + s.Name
}

// CallEdge is a directed edge from Caller to Callee.
type CallEdge struct {
	Caller    Symbol
	Callee    Symbol
	File      string
	Line      int
	Synthetic bool // true for virtual/inferred edges
}

// FunctionCaps holds the direct and transitive capabilities of a single function.
type FunctionCaps struct {
	Symbol         Symbol
	DirectCaps     capability.CapabilitySet
	TransitiveCaps capability.CapabilitySet
	Depth          int // max hops to nearest capability sink
}

// IRGraph is the normalized intermediate representation for a package.
type IRGraph struct {
	Calls     []CallEdge
	Functions map[string]FunctionCaps // Symbol.String() → FunctionCaps
}

// Context represents k-CFA calling context (k=1: immediate caller).
type Context struct {
	Caller Symbol
}

// String returns a string representation of the context.
func (c Context) String() string {
	if c.Caller.Package == "" && c.Caller.Name == "" {
		return "<entry>"
	}
	return c.Caller.String()
}

// ContextNode is a context-sensitive node in the call graph.
type ContextNode struct {
	Function Symbol
	Context  Context
}

// String returns a unique identifier for this context node.
func (cn ContextNode) String() string {
	return cn.Function.String() + "@" + cn.Context.String()
}

// FunctionSummary captures taint-relevant information per function.
type FunctionSummary struct {
	Node       ContextNode
	Sources    capability.CapabilitySet // Direct sources (env, network, fs:read)
	Sinks      capability.CapabilitySet // Direct sinks (exec, unsafe)
	Sanitizers capability.CapabilitySet // Sanitization (crypto)
	Effects    capability.CapabilitySet // All direct capabilities
	Transitive capability.CapabilitySet // Propagated from callees
	Depth      int                      // Max hops from capability
	Confidence float64                  // Min confidence across chain
	CallStack  []CallEdge               // Path to root capability
	Iteration  int                      // Fixpoint iteration when updated
}

// SCC represents a strongly connected component (cycle) in the call graph.
type SCC struct {
	ID      int
	Nodes   []ContextNode
	Summary FunctionSummary // Collapsed summary for entire SCC
}

// CSCallGraph is a context-sensitive call graph.
type CSCallGraph struct {
	Nodes        map[string]ContextNode     // key: ContextNode.String()
	Edges        map[string][]ContextNode   // caller → callees
	ReverseEdges map[string][]ContextNode   // callee → callers
	Summaries    map[string]FunctionSummary // key: ContextNode.String()
	SCCs         map[int]*SCC               // SCC ID → SCC
	NodeToSCC    map[string]int             // ContextNode → SCC ID
}

// NewCSCallGraph creates an empty context-sensitive call graph.
func NewCSCallGraph() *CSCallGraph {
	return &CSCallGraph{
		Nodes:        make(map[string]ContextNode),
		Edges:        make(map[string][]ContextNode),
		ReverseEdges: make(map[string][]ContextNode),
		Summaries:    make(map[string]FunctionSummary),
		SCCs:         make(map[int]*SCC),
		NodeToSCC:    make(map[string]int),
	}
}
