# AST v2 Design — gorisk

## Overview

This document describes the v2 analysis pipeline: what exists, what was wrong, and what changed.

---

## 1. Analysis Pipeline

```
Source files
    │
    ▼
[Language Adapter] (Go: go/packages + go/types; Node: regex + ParseBindings)
    │   • Per-file capability detection (DetectPackage / DetectFileAST)
    │   • Per-function capability detection (DetectFunctions)
    │
    ▼
[IR Graph] (ir.IRGraph)
    │   • Functions: Symbol → FunctionCaps (DirectCaps)
    │   • Calls: []CallEdge (symbol-resolved for Go, regex-inferred for Node)
    │
    ▼
[Interproc Engine] (internal/interproc)
    │   1. BuildCSCallGraph (k=1 CFA) — BFS from entry functions
    │   2. DetectSCCs (Tarjan) — collapse cycles
    │   3. ComputeFixpoint (worklist) — propagate capabilities across call graph
    │   4. AnalyzeInterprocedural — run taint rules on summaries
    │
    ▼
[FunctionSummary per node]
    │   • Effects: direct capabilities
    │   • Transitive: propagated from callees (with hop decay)
    │   • Sources / Sinks / Sanitizers: classified subsets
    │
    ▼
[Rollup to Packages]
    │   • Merge transitive caps from all functions into package.Capabilities
    │
    ▼
[Taint Analysis] (taint.Analyze on packages)
    │   • Source → Sink rules on package capability sets
    │   • Confidence-aware severity downgrade
    │
    ▼
[Scan Report]
    • CapabilityReports, HealthReports, TaintFindings
    • JSON / SARIF / text output
```

---

## 2. IR Schema

### Current (unchanged)

```go
// Symbol — named code entity
Symbol { Package, Name, Kind }

// CallEdge — directed call
CallEdge { Caller Symbol, Callee Symbol, File, Line, Synthetic bool }

// FunctionCaps — per-function capability container
FunctionCaps { Symbol, DirectCaps CapabilitySet, TransitiveCaps CapabilitySet, Depth int }

// IRGraph — package/module-level intermediate representation
IRGraph { Functions map[string]FunctionCaps, Calls []CallEdge }

// FunctionSummary — result of interprocedural analysis
FunctionSummary {
    Node       ContextNode
    Sources    CapabilitySet   // taint sources (env, network, fs:read)
    Sinks      CapabilitySet   // taint sinks (exec, unsafe, plugin)
    Sanitizers CapabilitySet   // sanitizer capabilities (crypto)
    Effects    CapabilitySet   // all direct capabilities
    Transitive CapabilitySet   // propagated from callees
    Depth      int             // max hops
    Confidence float64         // min confidence across chain
    CallStack  []CallEdge      // path to nearest capability
}
```

No structural changes to IR types were needed — the schema is already sufficient.

---

## 3. Summary Propagation Model

Capability confidence decays across call hops:

| Hop | Multiplier |
|-----|-----------|
| 0   | 1.00       |
| 1   | 0.70       |
| 2   | 0.55       |
| 3+  | 0.40 (stop)|

Fixpoint algorithm (worklist):
1. Initialize worklist with nodes in reverse topological order (leaves first)
2. Process each node: merge callee summaries with hop decay
3. If summary changes, re-enqueue callers
4. Repeat until convergence or max 1000 iterations
5. **v2 fix**: Use sorted `[]string` slice worklist instead of `map[string]bool` for deterministic iteration

SCC handling: Tarjan's algorithm detects cycles; collapsed SCC summary is reused for all nodes in the cycle (prevents infinite loops).

---

## 4. Confidence/Uncertainty Model

| Evidence type             | Confidence |
|---------------------------|-----------|
| import statement          | 0.90       |
| destructured import       | 0.85       |
| install script            | 0.85       |
| chained require call      | 0.80       |
| resolved var call         | 0.80       |
| bare destructured call    | 0.85       |
| callSite pattern (Go)     | 0.75       |
| callSite pattern (Node regex) | 0.60  |

Severity downgrade: if `min(source_conf, sink_conf) < 0.70`, taint severity is downgraded one level (HIGH→MEDIUM, MEDIUM→LOW).

---

## 5. Taint Path Finding (v2)

**Problem**: `traceTaintFlow` was a 1-hop stub. For multi-hop flows it returned the same function as both source and sink, producing misleading paths.

**Fix**: BFS from all nodes with `source` capability, following call edges, until a node with `sink` capability is reached. Returns the actual call path.

Algorithm:
```
BFS(callGraph, sourceNodes, sink):
    queue = [(node, path=[])]
    visited = {}
    while queue not empty:
        node, path = dequeue
        if visited[node]: continue
        visited[node] = true
        summary = summaries[node]
        if summary.Sinks.Has(sink):
            return TaintFlow{source=path[0], sink=node, callPath=path}
        for callee in edges[node]:
            enqueue (callee, path + [edge])
    return nil
```

---

## 6. Cache Strategy (v2)

**Problem**: `CodeHash` was hardcoded to `"dev"` — cache never invalidated on code changes.

**Fix**: `ComputeCodeHash(dir, files)` hashes the content of relevant source files with SHA256:
```
hash = SHA256(sorted filenames + file content)
```
This ensures cache entries are invalidated when source files change, while being stable when files are unchanged.

---

## 7. Node.js Function Boundary Detection (v2)

**Problem**: `findFunctionEnd` counted raw `{`/`}` characters, failing when strings or comments contained braces.

**Fix**: State machine parser with states:
- `normal` — counts `{`/`}` depth
- `inSingleQuote`, `inDoubleQuote`, `inTemplateLiteral` — skips content
- `inLineComment` — skips to end of line
- `inBlockComment` — skips to `*/`
- Handles escape sequences (`\"`, `\'`, `\\`)

---

## 8. Node Interprocedural Results (v2)

**Problem**: `runInterproceduralAnalysis` in the Node adapter ran the full interprocedural engine but discarded the context-sensitive call graph. Enhanced capabilities from callee analysis were lost.

**Fix**: After `interproc.RunAnalysis`, roll up function summaries to package capabilities using the same `rollupToPackages` pattern as the Go adapter. This surfaces transitive capabilities that were previously invisible at the package level.
