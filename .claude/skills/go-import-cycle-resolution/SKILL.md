---
name: go-import-cycle-resolution
description: |
  Resolve "import cycle not allowed" errors in Go. Use when: (1) Adding a new
  import causes "import cycle not allowed" compile error, (2) Two packages need
  to reference each other's types, (3) Refactoring creates circular dependencies
  between internal packages. Covers interface-based abstraction, shared package
  extraction, dependency inversion, and runtime configuration patterns for
  breaking cycles while maintaining functionality.
author: Claude Code
version: 1.0.0
date: 2026-02-19
---

# Go Import Cycle Resolution

## Problem

Go's compiler prevents import cycles with the error `import cycle not allowed`.
This occurs when package A imports package B, and package B (directly or
indirectly) imports package A. While this design keeps dependency graphs clean,
it can be frustrating when legitimate architectural needs seem to require
circular dependencies.

## Context / Trigger Conditions

**Exact Error Message:**
```
import cycle not allowed
package github.com/user/project/internal/graph
  imports github.com/user/project/internal/taint
  imports github.com/user/project/internal/graph
```

**Common Scenarios:**
- Adding a new type to a core package that references types from another package
- Extending a data model to include analysis results from a different layer
- Refactoring where two packages now need bidirectional awareness
- Test files creating cycles when importing testing utilities

## Why Go Enforces This

Go blocks import cycles because:
- Prevents lazy dependency management and forces clear architectural thinking
- Keeps build times fast by enabling parallel compilation
- Makes the dependency graph acyclic, simplifying analysis and tooling
- Without cycles, the compiler knows unambiguous initialization order

## Solution Patterns

### Pattern 1: Extract Shared Types to Common Package

**Best for:** Type definitions shared between multiple packages

**Example from gorisk:**
```
❌ Before (cycle):
internal/graph/graph.go → imports internal/taint (for TaintFinding type)
internal/taint/taint.go → imports internal/graph (for Package type)

✅ After (no cycle):
internal/graph/graph.go → no taint import
internal/taint/taint.go → imports internal/graph (for Package type)
Commands compute findings separately without storing in graph
```

**Steps:**
1. Identify the shared types causing the cycle
2. Create a new package for common types (e.g., `internal/types`)
3. Move shared types to the new package
4. Have both original packages import the common package

**Trade-off:** Can lead to "god packages" if overused. Only extract truly shared types.

### Pattern 2: Interface-Based Abstraction (Dependency Inversion)

**Best for:** When one package needs behavior but not implementation details

**Example:**
```go
// ❌ Before: direct dependency creates cycle
package analyzer
import "myapp/storage"  // storage also imports analyzer

func Process(s *storage.Store) { ... }

// ✅ After: dependency inversion
package analyzer

type DataStore interface {
    Get(key string) ([]byte, error)
    Set(key string, value []byte) error
}

func Process(s DataStore) { ... }  // No import of storage package

// In main or config package (no cycle):
import "myapp/analyzer"
import "myapp/storage"

analyzer.Process(storage.NewStore())
```

**Steps:**
1. Define an interface in the package that needs the functionality
2. Make the other package's type implement that interface
3. Accept the interface instead of the concrete type
4. Wire up concrete implementations at runtime (in main or init)

**Trade-off:** Adds indirection but increases testability.

### Pattern 3: Runtime Configuration / Registration

**Best for:** Plugin-like architectures or route registration

**Example:**
```go
// ❌ Before: router imports all handlers
package router
import "myapp/handlers/users"
import "myapp/handlers/posts"

func Setup() {
    r.Handle("/users", users.Handler())
    r.Handle("/posts", posts.Handler())
}

// ✅ After: handlers register themselves
package router

var routes = make(map[string]http.Handler)

func Register(path string, h http.Handler) {
    routes[path] = h
}

// In each handler package's init():
package users
import "myapp/router"

func init() {
    router.Register("/users", Handler())
}
```

**Steps:**
1. Create a registration function in the lower-level package
2. Have higher-level packages call register in `init()` or main
3. Remove direct imports from the lower-level package

**Trade-off:** Makes the call graph less explicit but enables plugin patterns.

### Pattern 4: Pass Data Separately (Avoid Storing in Shared Types)

**Best for:** Analysis results or computed data that doesn't belong in the core model

**Example from gorisk:**
```go
// ❌ Before: trying to add TaintFindings to DependencyGraph
type DependencyGraph struct {
    Packages      map[string]*Package
    TaintFindings []taint.TaintFinding  // Creates cycle!
}

// ✅ After: keep them separate, compute when needed
type DependencyGraph struct {
    Packages map[string]*Package
}

// In command layer:
g, _ := graph.Load(dir)
findings := taint.Analyze(g.Packages)  // Computed separately
```

**Steps:**
1. Recognize that not all related data needs to be in the same struct
2. Keep the core data model minimal
3. Compute derived data where it's needed (commands, handlers, etc.)
4. Pass both pieces of data separately if needed by consumers

**Trade-off:** Slight duplication in calls but clearer separation of concerns.

## Verification

After applying a pattern:

1. **Build succeeds:**
   ```bash
   go build ./...
   ```

2. **Check dependency graph:**
   ```bash
   go mod graph | grep mypackage
   ```

3. **Verify no test cycles:**
   ```bash
   go list -f '{{.ImportPath}} {{.Imports}}' ./...
   ```

## Decision Matrix

| Situation | Recommended Pattern |
|-----------|-------------------|
| Shared type definitions | Extract to common package |
| Need behavior, not implementation | Interface-based abstraction |
| Plugin/registration system | Runtime configuration |
| Analysis results on core model | Pass data separately |
| Testing utilities | Move to separate testing package |

## Common Mistakes

1. **Creating "util" or "common" packages for everything** - Only extract truly shared types
2. **Over-using interfaces** - Don't abstract just to avoid imports
3. **Hiding dependencies in init()** - Makes code harder to understand
4. **Not questioning the architecture** - Sometimes the cycle reveals a design problem

## Notes

- Import cycles in test files (`_test.go`) can sometimes be resolved by moving test helpers to a separate `testutil` package
- The `internal/` directory convention helps enforce package boundaries
- Consider whether the cycle indicates a missing abstraction layer in your architecture
- Tools like `goimportcycle` can visualize dependency graphs to understand complex cycles

## Example: Complete Resolution

**Problem encountered in gorisk:**

Wanted to store taint analysis results in the dependency graph, but:
- `internal/graph` would need to import `internal/taint` for the `TaintFinding` type
- `internal/taint` already imports `internal/graph` for the `Package` type
- Result: `import cycle not allowed`

**Solution applied:**

Pattern 4 (Pass Data Separately):
1. Kept `DependencyGraph` without `TaintFindings` field
2. Commands compute taint findings separately: `findings := taint.Analyze(g.Packages)`
3. Both data structures passed to report generation independently
4. No import added to `graph` package, avoiding the cycle

**Why this worked:**
- Taint findings are derived data, not core to the dependency graph
- Commands/handlers are the right place to compose different analyses
- Keeps `internal/graph` focused on dependency modeling
- Maintains backward compatibility

## References

- [How to fix import cycle in Go](https://medium.com/@gabriel.2008grs/how-to-fix-import-cycle-in-go-f2fb3457685b)
- [Go import cycles: three strategies for dealing with them](https://www.dolthub.com/blog/2025-03-14-go-import-cycle-strategies/)
- [Managing Circular Dependencies in Go: Best Practices](https://medium.com/@cosmicray001/managing-circular-dependencies-in-go-best-practices-and-solutions-723532f04dde)
- [Dealing With Import Cycles in Go](https://mantish.com/post/dealing-with-import-cycle-go/)
- [Breaking the import cycle in Go](https://www.species.gg/blog/solving-go-import-cycles)
