# gorisk Performance Guide

## Target Scan Times

| Project size | Expected time | Notes |
|---|---|---|
| Small (< 50 deps) | < 3 s | Typical Go CLI app |
| Medium (50–200 deps) | 3–10 s | Typical web service |
| Large (200–500 deps) | 10–30 s | Monorepo member |
| Very large (500+ deps) | 30–90 s | Full monorepo |

These targets assume `gorisk scan` (offline, no `--online` flag). Health/CVE
scoring (`--online`) adds 2–15 s depending on network latency and number of modules.

## Profiling with --timings

Use `gorisk scan --timings` to get a per-phase breakdown:

```
=== Timings ===
graph load                   1.23s
capability detect            0.45s
engines (parallel)           0.89s
output formatting            0.02s
────────────────────────────────────────
total                        2.59s
```

## Phase Descriptions

| Phase | What it does | Dominant cost driver |
|---|---|---|
| graph load | Parse lockfiles, build DependencyGraph | Lockfile size, file I/O |
| capability detect | Walk source files, match patterns | Number of .go/.js/.py files |
| engines (parallel) | Topology + integrity + versiondiff | Lockfile complexity |
| AST/interproc | Interprocedural call graph analysis | Package count, call depth |
| output formatting | Render text/JSON/SARIF | Number of findings |

## Optimisation Tips

### Skip AST analysis for large repos

The interprocedural AST pipeline is the most expensive phase for large Go
projects. It runs automatically when Go SSA packages are available. To disable:

```bash
GORISK_LANG=go gorisk scan  # still does import-level analysis
```

### Use --exclude-packages for known-safe deps

```json
{
  "exclude_packages": [
    "github.com/myorg/*",
    "golang.org/x/*"
  ]
}
```

### Use --top N to limit output

```bash
gorisk scan --top 10  # show only 10 highest-risk packages
```

### Cache health scores

The `--online` flag caches GitHub/OSV responses in `~/.cache/gorisk/` for 24 h.
Repeated scans of the same project version will be significantly faster.

## Benchmark Results

Run the included benchmarks with:

```bash
go test -bench=. -benchtime=3x ./cmd/gorisk/scan/...
```

Example results on a 2024 MacBook Pro (M3, 16 GB RAM):

| Benchmark | Time |
|---|---|
| BenchmarkScanGoProject | ~850 ms/op |
| BenchmarkScanNodeProject | ~120 ms/op |

These are measured against the `testdata/golden/` fixture projects (minimal
dependencies). Real projects will be slower proportional to dependency count.

## Memory Usage

gorisk holds the entire dependency graph in memory during a scan. Expected
peak RSS:

| Deps | Peak RSS |
|---|---|
| 50 | ~25 MB |
| 200 | ~80 MB |
| 500 | ~200 MB |

If you observe excessive memory usage, check for circular dependency loops in
the lockfile — gorisk uses sorted iteration to avoid non-termination but a very
deep graph can still allocate heavily.
