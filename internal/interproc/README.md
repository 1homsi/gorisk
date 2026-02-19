# Interprocedural Analysis Engine

This package provides context-sensitive interprocedural analysis for gorisk, enabling more precise capability tracking and taint detection across function boundaries.

## Features

- **Context-Sensitive Call Graph (k-CFA)**: Distinguishes different calling contexts (k=1: immediate caller)
- **SCC Detection**: Handles recursive call cycles using Tarjan's algorithm
- **Worklist Fixpoint**: Converges on transitive capabilities through iterative propagation
- **Persistent Caching**: Speeds up repeated analysis by caching function summaries
- **Enhanced Taint Analysis**: Tracks source→sink flows across function calls with full call stacks

## Architecture

```
Context-Sensitive   →  Summary      →  SCC Detector
Call Graph Builder     Generator       (Tarjan)
        ↓                  ↓               ↓
Worklist Fixpoint   ←  Lattice Ops  ←  Cache Manager
        ↓
Per-Function Taint Analysis
```

## Usage

### Running Analysis

The interprocedural engine is **enabled by default**:

```bash
gorisk scan
```

### Verbose Output

Enable detailed logging to see the analysis progress:

```bash
gorisk scan --verbose
```

Or using environment variable (backward compatible):

```bash
GORISK_VERBOSE=1 gorisk scan
```

This shows:
- Call graph construction (nodes, edges, context cloning)
- SCC detection results
- Fixpoint iteration progress
- Cache hit/miss statistics
- Taint flow analysis results

### Disable Caching

To clear the cache manually:

```bash
rm -rf ~/.cache/gorisk/summaries
```

### Configure Analysis Options

```go
import "github.com/1homsi/gorisk/internal/interproc"

opts := interproc.AnalysisOptions{
    ContextSensitivity: 1,    // k for k-CFA (0=insensitive, 1=caller-sensitive)
    MaxIterations:      1000, // Max fixpoint iterations
    EnableCache:        true, // Enable persistent caching
    CacheDir:           "",   // Default: $HOME/.cache/gorisk/summaries
}

csGraph, findings, err := interproc.RunAnalysis(irGraph, opts)
```

## Algorithm Details

### Context Sensitivity (k-CFA)

The engine uses **k=1** calling context sensitivity by default:
- Each function is analyzed separately for each unique immediate caller
- Prevents over-approximation when functions are called from different contexts
- Balances precision with performance (k=0 too imprecise, k≥2 too expensive)

### SCC Detection

Strongly connected components (recursive call cycles) are detected using **Tarjan's algorithm**:
- Collapses SCCs into "super-nodes" with unified summaries
- Limits intra-SCC iterations to 3 to prevent infinite loops
- Ensures termination even with complex mutual recursion

### Fixpoint Computation

Capabilities propagate bottom-up (leaves → roots) using a **worklist algorithm**:
1. Initialize worklist with all functions in reverse topological order
2. For each function, compute summary from callees
3. If summary changes, re-enqueue all callers
4. Repeat until convergence (or max iterations)

**Confidence Decay**: Capabilities lose confidence as they propagate:
- Hop 0 (direct): 1.00
- Hop 1: 0.70
- Hop 2: 0.55
- Hop 3+: 0.40

**Depth Limit**: Stops propagating after 3 hops to maintain precision.

### Persistent Caching

Function summaries are cached to disk for incremental analysis:
- **Cache Key**: Function + context + direct capabilities + callee hashes + code hash
- **Format**: JSON (human-readable, debuggable)
- **Location**: `$HOME/.cache/gorisk/summaries/<package>/<hash>.json`
- **Invalidation**: On file mtime change, dependency change, or version mismatch

**Cache Hit Rate**: Typically >90% on unchanged code.

## Testing

Run the test suite:

```bash
go test ./internal/interproc/... -v
```

Key test cases:
- **SCC Detection**: Simple cycles, multiple SCCs, self-loops, DAGs
- **Fixpoint**: Linear chains, cycles, convergence, depth limits
- **Context Sensitivity**: Context cloning, merging (k=0 vs k=1)

## Performance

Benchmarks on the gorisk codebase (>300 functions):
- **First run**: ~500ms (no cache)
- **Second run**: ~50ms (90%+ cache hits)
- **Memory**: ~10MB for typical projects

## Comparison: Old vs New

| Feature | Old (3-Pass) | New (Interprocedural) |
|---------|--------------|------------------------|
| Context | Insensitive | k=1 CFA |
| Cycles | Convergence heuristic | Explicit SCC detection |
| Depth | Fixed 3 passes | Worklist until convergence |
| Taint | Package-level only | Function-level with call stacks |
| Caching | None | Persistent JSON cache |
| Precision | Medium | High |

## Future Work

- **k=2 Analysis**: Two-level calling context (currently limited to k=1)
- **Field-Sensitive**: Track capabilities per struct field
- **Path-Sensitive**: Distinguish control-flow paths within functions
- **Sanitizer Detection**: Recognize validation/encoding functions
- **Binary Cache Format**: Faster serialization (currently JSON)

## References

- [Reps et al., "Precise Interprocedural Dataflow Analysis via Graph Reachability"](https://dl.acm.org/doi/10.1145/237721.237727)
- [Tarjan, "Depth-First Search and Linear Graph Algorithms"](https://epubs.siam.org/doi/10.1137/0201010)
- [Cousot & Cousot, "Abstract Interpretation: A Unified Lattice Model"](https://dl.acm.org/doi/10.1145/512950.512973)
