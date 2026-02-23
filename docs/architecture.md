# gorisk Architecture

gorisk is a multi-language supply-chain risk engine. This document describes its
internal architecture and data flow.

## High-Level Pipeline

```
Project directory
      │
      ▼
  Language detection  ──► internal/analyzer/analyzer.go
      │
      ▼
  Graph construction  ──► internal/adapters/{go,node,php,python,java,rust,ruby}/
      │                    Produces: *graph.DependencyGraph
      ▼
  Capability detection ──► internal/capability/ + languages/*.yaml
      │                    Produces: capability.CapabilitySet per package
      ▼
  AST/Interprocedural  ──► internal/astpipeline/
  analysis             ──► internal/interproc/   (k=1 CFA)
      │                    Produces: ReachabilityHints, TaintFindings
      ▼
  Multi-engine scoring ──► internal/priority/score.go (ComputeFinal)
      │                    = semantic + diff + integrity + topology
      ▼
  Policy enforcement   ──► cmd/gorisk/scan/scan.go
      │
      ▼
  Output               ──► internal/report/{text,json,sarif}.go
```

## Core Packages

### internal/graph

`DependencyGraph` is the central data structure: a module-level DAG with package
nodes, edges, and per-package capability sets. All language adapters return a
`*graph.DependencyGraph`.

### internal/capability

`CapabilitySet` holds typed capabilities (`exec`, `network`, `fs:read`, etc.) with
per-capability `CapabilityEvidence` (file, line, via, confidence). The capability
taxonomy is defined in `internal/capability/types.go`.

**Capability weights** (used in semantic scoring):
- `exec` = 20
- `unsafe` = 25
- `plugin` = 20
- `network` = 15
- `fs:write` = 10
- `fs:read` = 5
- `env` = 5
- `crypto` = 5
- `reflect` = 5

**Risk thresholds**: LOW < 10, MEDIUM ≥ 10, HIGH ≥ 30.

### internal/priority

`ComputeFinal()` combines four engine signals into one additive score (capped at 100):

```
final = semantic + diff + integrity + topology
```

- **semantic** = `cap_score × reach_mod × taint_mod`
- **diff** = new/escalated packages vs base lockfile (0–20, `versiondiff` engine)
- **integrity** = checksum coverage + path/git dep violations (0–20, `integrity` engine)
- **topology** = lockfile fanout/depth/churn/skew/dups (0–20, `topology` engine)

### internal/interproc

Context-sensitive interprocedural analysis (k=1 CFA, Tarjan's SCC cycle detection,
fixpoint worklist). Produces per-function capability summaries and taint paths via
BFS multi-hop traversal (max depth 3).

**Hop multipliers**: hop 0 → 1.0, hop 1 → 0.70, hop 2 → 0.55, hop 3+ → 0.40.

### Language Adapters

Each adapter implements `analyzer.Analyzer`:

```go
type Analyzer interface {
    Name() string
    Load(dir string) (*graph.DependencyGraph, error)
}
```

| Language | Lockfile(s) | Source scan |
|----------|-------------|-------------|
| Go | go.sum | AST + SSA + CFA |
| Node.js | package-lock.json, yarn.lock, pnpm-lock.yaml | Regex + AST |
| PHP | composer.lock | Regex |
| Python | poetry.lock, Pipfile.lock, requirements.txt, pyproject.toml | Regex |
| Java | pom.xml, gradle.lockfile, build.gradle | Regex |
| Rust | Cargo.lock, Cargo.toml | Regex |
| Ruby | Gemfile.lock, Gemfile | Regex |

### Pattern Files

Capability patterns are defined in `languages/{lang}.yaml` with two sections:
- `imports:` — module/package import names → capabilities
- `call_sites:` — code substrings → capabilities

**Pattern key format requirements**:
- Go: must be `pkg.Func` (e.g., `os.ReadFile`)
- Node: must be namespaced (e.g., `fs.readFile(`, `child_process.exec(`)
- PHP: must be namespaced facades (e.g., `Http::get(`, `Storage::put(`)

### Public SDK

`pkg/gorisk/` exposes a stable programmatic API with semver guarantees:

```go
scanner := gorisk.NewScanner(gorisk.ScanOptions{
    Dir:    "/path/to/project",
    Lang:   "go",
    Policy: gorisk.DefaultPolicy(),
})
result, err := scanner.Scan()
```

### Plugin System

Plugins are native Go plugins (`go build -buildmode=plugin`) placed in
`~/.gorisk/plugins/*.so`. They must export `CapabilityDetector` and/or `RiskScorer`
symbols matching the interfaces in `pkg/gorisk/plugin.go`.

## Data Flow for Taint Analysis

```
Package capabilities (source caps ∩ sink caps)
      │
      ▼
internal/taint/taint.go: Analyze(pkgs)
      │
      ├── Single-package: check each pkg for (source ∩ sink)
      │
      └── Interprocedural: traceTaintFlow BFS across call edges
              Max hops: 3
              Produces: TaintFinding{Source, Sink, Path, Confidence}
```

**Taint rules** (from taint.go): `env → exec`, `network → exec`, `network → fs:write`,
`fs:read → network`, `env → fs:write`, `env → network`.

## Caching

`internal/cache/` provides a file-backed cache at `~/.cache/gorisk/`. Cache keys are
SHA-256 hashes of the content being cached. Current TTLs:
- Health/CVE scores (GitHub + OSV APIs): 24 hours

## REST API (gorisk serve)

`gorisk serve --port 8080` exposes:
- `GET /health` — server health check
- `POST /scan` — runs a scan on the given dir, returns `ScanResult` JSON

See `cmd/gorisk/serve/serve.go` for request/response schemas.
