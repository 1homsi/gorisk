---
name: go-missing-file-recovery
description: |
  Fix "undefined: X" compilation errors during git commit/push in Go projects.
  Use when: (1) pre-commit hooks fail with "undefined: FunctionName", (2) type
  checker errors show missing symbols that should exist, (3) implementing large
  features with multiple interdependent files. Solution: create missing files
  with expected symbols/functions based on error messages and calling code.
author: Claude Code
version: 1.0.0
date: 2026-02-19
---

# Go Missing File Recovery

## Problem
When implementing large features in Go, you may reference functions or types in
one file before creating the file that defines them. Pre-commit hooks (like
golangci-lint) fail with "undefined: X" errors, blocking commits even though
you know what files need to exist.

## Context / Trigger Conditions
- Git commit fails with pre-commit hook errors like:
  ```
  undefined: BuildCSCallGraph
  undefined: Cache
  undefined: NewCache
  undefined: SummariesEqual
  ```
- Type checker reports missing symbols across multiple files
- You're implementing a new package with interdependent files
- Some files reference symbols that exist in not-yet-created files

## Solution

### Step 1: Identify Missing Symbols
Parse the compilation errors to extract what's undefined:
```bash
# Example error output:
# internal/interproc/interproc.go:44:13: undefined: BuildCSCallGraph
# internal/interproc/fixpoint.go:49:9: undefined: SummariesEqual
```

Group by likely file:
- `BuildCSCallGraph` → probably in `context.go` (call graph construction)
- `SummariesEqual` → probably in `lattice.go` (comparison/equality)
- `Cache`, `NewCache` → probably in `cache.go` (cache management)

### Step 2: Examine Calling Code
Read the files that reference the undefined symbols to understand:
- Function signatures expected (parameters, return types)
- Purpose and behavior (from context of calls)
- Package imports needed

Example:
```go
// From interproc.go line 44:
csGraph := BuildCSCallGraph(irGraph, k)
// Expects: BuildCSCallGraph(ir.IRGraph, int) *ir.CSCallGraph
```

### Step 3: Create Missing Files
Create each missing file with:
1. Package declaration
2. Required imports
3. Function/type signatures (initially with stub implementations)

```go
// internal/interproc/cache.go
package interproc

import (
    "github.com/yourproject/internal/ir"
)

type Cache struct {
    // Fields determined from usage
}

func NewCache(dir string) *Cache {
    // Stub implementation
    return &Cache{}
}
```

### Step 4: Iterate Until Compilation Succeeds
1. Run `go build` or trigger pre-commit hook again
2. Fix new errors (type mismatches, missing methods)
3. Repeat until all files compile

### Step 5: Implement Actual Logic
Once files exist and compile, implement the actual logic for each function.

## Verification
```bash
# Should now pass without undefined errors:
git add .
git commit -m "your message"

# Or directly test compilation:
go build ./...
```

## Example

**Scenario**: Implementing interprocedural analysis, interproc.go references
BuildCSCallGraph, but context.go doesn't exist yet.

**Error**:
```
internal/interproc/interproc.go:44:13: undefined: BuildCSCallGraph
```

**Solution**:
```bash
# 1. Read the calling code
$ grep -A2 -B2 BuildCSCallGraph internal/interproc/interproc.go
csGraph := BuildCSCallGraph(irGraph, k)

# 2. Determine expected signature
# Expects: BuildCSCallGraph(ir.IRGraph, int) *ir.CSCallGraph

# 3. Create missing file
$ cat > internal/interproc/context.go <<'EOF'
package interproc

import "github.com/1homsi/gorisk/internal/ir"

func BuildCSCallGraph(irGraph ir.IRGraph, k int) *ir.CSCallGraph {
    // Stub: return empty graph
    return &ir.CSCallGraph{
        Nodes: make(map[string]ir.ContextNode),
        // ... other required fields
    }
}
EOF

# 4. Verify compilation
$ go build ./internal/interproc
# Success!
```

## Notes
- **Don't guess implementations**: Create stubs that compile, implement logic later
- **Check for existing files**: Use `find . -name "*.go"` to avoid duplicating files
- **Look for patterns**: File names often match their primary type/function
  (cache.go → Cache type, context.go → context-related functions)
- **Use IDE hints**: If using an IDE, it may suggest "Create function" quick-fixes
- **Consider package structure**: Keep related functionality in same file
  (all cache operations in cache.go, all SCC logic in scc.go)

## References
- [Effective Go - Package Structure](https://go.dev/doc/effective_go#package-names)
- [Go Build Constraints](https://pkg.go.dev/cmd/go#hdr-Build_constraints)
