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
