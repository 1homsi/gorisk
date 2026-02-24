# gorisk

<img src="assets/gorisk.png" alt="gorisk" width="390"/>

**Behavioral supply-chain risk intelligence from code structure.**
Maps what your dependencies *can do* — network access, exec, filesystem writes, unsafe pointers — not just what CVEs they carry.

---

## Why gorisk

| Tool | CVEs | Capabilities | Evidence | Upgrade risk | Blast radius | Polyglot | Offline | Free |
|------|------|-------------|---------|--------------|-------------|----------|---------|------|
| govulncheck | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Snyk | ✅ | ❌ | ❌ | partial | ❌ | partial | ❌ | SaaS |
| goda | ❌ | ❌ | ❌ | ❌ | partial | ❌ | ✅ | ✅ |
| GoSurf | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **gorisk** | via OSV | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** |

Key differentiators:

- **Polyglot** — 22 languages: Go, Node.js, PHP, Python, Rust, Java, Ruby, C#/.NET, Dart, Swift, Elixir, Kotlin, Scala, C/C++, Haskell, Clojure, Erlang, OCaml, Julia, R, Perl, Lua. Every language supports the full feature suite — scan, reachability, upgrade intelligence, PR diff.
- **Capability detection** — detect which packages can read files, make network calls, spawn processes, or use `unsafe`/`eval`. Know *what your dependencies can do* before they're in production.
- **Evidence + confidence** — every capability detection is backed by file path, line number, match context, and a confidence score (import = 90%, call site = 75%, install script = 85%).
- **Capability diff** — compare two versions of a dependency and detect capability escalation. If `v1.2.3 → v1.3.0` quietly added `exec` or `network`, gorisk flags it as a supply chain risk signal.
- **Deterministic output** — all output is sorted; every scan produces a short SHA-256 graph checksum so CI can detect silent graph changes between runs.
- **CVE listing** — full list of OSV vulnerability IDs per module, not just a count.
- **Blast radius** — simulate removing a module and see exactly which packages and binaries break, plus LOC impact.
- **Upgrade risk** — diff exported symbols between versions (Go) or lockfile versions (all other languages) to detect breaking API changes before you upgrade.
- **Health scoring** — combines commit activity, release cadence, archived status, and CVE count into a single score (parallel, 10 workers).
- **Reachability** — prove a capability is reachable from `main` via callgraph (Go) or import graph (all other languages). Supports `--entry` to target a specific binary.
- **History + trend** — snapshot risk over time, diff between snapshots, view score sparklines per module.
- **CI-native** — SARIF output compatible with GitHub Code Scanning. Exit codes for policy gating. `--timings` flag for build profiling.

---

## Install

```bash
go install github.com/1homsi/gorisk/cmd/gorisk@latest
```

---

## Language support

gorisk auto-detects the language from the project directory. Use `--lang` to override.

```bash
gorisk scan              # auto-detect
gorisk scan --lang go    # force Go
gorisk scan --lang node  # force Node.js
gorisk scan --lang python
gorisk scan --lang java
gorisk scan --lang rust
# ... any --lang value from the table below
```

When both `go.mod` and `package.json` are present (monorepo), both analyzers run and their dependency graphs are merged.

### Supported languages

All 22 languages support: `scan`, `capabilities`, `explain`, `graph`, `reachability`, `upgrade`, `pr`, `sbom`, `licenses`, `viz`, `history`, `impact`, and `trace`.

All 22 languages use **✅ Full** analysis depth — deep AST + interprocedural callgraph analysis with function-level capability propagation.

| Language | `--lang` | Analysis depth | Detection signal | Lockfile / manifest |
|----------|----------|---------------|-----------------|---------------------|
| **Go** | `go` | ✅ Full | `go.mod` | `go.mod` + `go list`; `go.work` workspace |
| **Node.js** | `node` | ✅ Full | `package.json` | `package-lock.json` v1/v2/v3, `yarn.lock`, `pnpm-lock.yaml`; npm/yarn/pnpm workspaces |
| **PHP** | `php` | ✅ Full | `composer.json` / `composer.lock` | `composer.lock`; Laravel, Symfony, bare Composer |
| **Python** | `python` | ✅ Full | `pyproject.toml` / `requirements.txt` | `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml` |
| **Java** | `java` | ✅ Full | `pom.xml` / `build.gradle` | `pom.xml`, `gradle.lockfile`, `build.gradle` / `build.gradle.kts` |
| **Rust** | `rust` | ✅ Full | `Cargo.toml` | `Cargo.lock`, `Cargo.toml` |
| **Ruby** | `ruby` | ✅ Full | `Gemfile` / `Gemfile.lock` | `Gemfile.lock`, `Gemfile` |
| **C#/.NET** | `dotnet` | ✅ Full | `packages.lock.json` / `*.csproj` | NuGet `packages.lock.json`, `.csproj` PackageReference |
| **Dart/Flutter** | `dart` | ✅ Full | `pubspec.lock` / `pubspec.yaml` | `pubspec.lock`, `pubspec.yaml` |
| **Swift** | `swift` | ✅ Full | `Package.resolved` / `Package.swift` | `Package.resolved` v1/v2/v3, `Package.swift` |
| **Elixir** | `elixir` | ✅ Full | `mix.lock` / `mix.exs` | `mix.lock`, `mix.exs` |
| **Kotlin** | `kotlin` | ✅ Full | `libs.versions.toml` / `build.gradle.kts` | `gradle/libs.versions.toml`, `build.gradle.kts`, `build.gradle` |
| **Scala** | `scala` | ✅ Full | `build.sbt` | `build.sbt` |
| **C/C++** | `cpp` | ✅ Full | `vcpkg.json` / `conanfile.py` | `vcpkg.json`, `conanfile.py`, `conanfile.txt` |
| **Haskell** | `haskell` | ✅ Full | `cabal.project.freeze` / `stack.yaml.lock` | `cabal.project.freeze`, `stack.yaml.lock`, `*.cabal` |
| **Clojure** | `clojure` | ✅ Full | `deps.edn` / `project.clj` | `deps.edn` (tools.deps), `project.clj` (Leiningen) |
| **Erlang/OTP** | `erlang` | ✅ Full | `rebar.lock` / `rebar.config` | `rebar.lock`, `rebar.config` |
| **OCaml** | `ocaml` | ✅ Full | `*.opam.locked` / `opam.locked` | `*.opam.locked`, `opam.locked`, `*.opam` |
| **Julia** | `julia` | ✅ Full | `Manifest.toml` | `Manifest.toml`, `Project.toml` |
| **R** | `r` | ✅ Full | `renv.lock` / `DESCRIPTION` | `renv.lock`, `DESCRIPTION` |
| **Perl** | `perl` | ✅ Full | `cpanfile.snapshot` / `cpanfile` | `cpanfile.snapshot` (Carton), `cpanfile` |
| **Lua** | `lua` | ✅ Full | `luarocks.lock` / `*.rockspec` | `luarocks.lock`, `*.rockspec` |

> **Full analysis** resolves interprocedural call chains across package boundaries — gorisk traces `main()` → helper → os/exec and scores the capability at each hop with confidence decay. All 22 languages have function-boundary detection, call edge extraction, and are wired through the k=1 CFA context-sensitive fixpoint engine.

Want to add a language? See [Contributing](#contributing).

---

## Capability taxonomy

All languages map to the same 9 capabilities. Risk level is derived from the total weight: **LOW** < 10, **MEDIUM** ≥ 10, **HIGH** ≥ 30.

| Capability | Weight | Meaning |
|-----------|--------|---------|
| `fs:read` | 5 | Reads from the filesystem |
| `fs:write` | 10 | Writes to or deletes files |
| `network` | 15 | Makes outbound network connections |
| `exec` | 20 | Spawns subprocesses or shell commands |
| `env` | 5 | Reads environment variables |
| `crypto` | 5 | Uses cryptographic primitives |
| `reflect` | 5 | Uses runtime reflection |
| `unsafe` | 25 | Bypasses memory/type safety (`unsafe`, `eval`, `vm`) |
| `plugin` | 20 | Loads or executes external code at runtime |

For the full per-language detection reference (imports, call-site patterns, confidence levels, and AST detection for all 22 supported languages), see **[docs/capability-detection.md](docs/capability-detection.md)**.

---

## Commands

### `gorisk scan`

Full scan: capabilities + health scoring + CVE listing + CI gate. Prints a **graph checksum** for reproducibility.

```bash
# Basic
gorisk scan

# Force language
gorisk scan --lang go
gorisk scan --lang node

# Output formats
gorisk scan --json
gorisk scan --sarif > results.sarif

# CI failure threshold
gorisk scan --fail-on medium      # fail if any MEDIUM+ risk package
gorisk scan --fail-on low         # strictest: fail on any capability

# Policy file (see Policy section below)
gorisk scan --policy .gorisk-policy.json

# Limit output to top N packages by risk score
gorisk scan --top 10

# Filter to a specific module and its transitive deps
gorisk scan --focus github.com/foo/bar

# Hide findings below 65% confidence
gorisk scan --hide-low-confidence

# Monorepo: merge all workspace members (go.work / npm/pnpm workspaces)
gorisk scan --workspace

# Diff against a base ref (requires git)
gorisk scan --base origin/main

# Online mode: include health scores and CVE data
gorisk scan --online

# Performance instrumentation
gorisk scan --timings

# Combination
gorisk scan --policy policy.json --fail-on high --json
```

**Output (text):**

```
graph checksum: a3f2b1c9d5e78f01

=== Capability Report ===

PACKAGE                  MODULE                   CAPABILITIES        SCORE  RISK
─────────────────────────────────────────────────────────────────────────────────
golang.org/x/net/http2   golang.org/x/net         network               15  MEDIUM
os/exec                  stdlib                   exec                  20  HIGH

=== Health Report ===

MODULE            VERSION       SCORE  CVEs  STATUS
─────────────────────────────────────────────────
golang.org/x/net  v0.25.0          85     0  OK

✓ PASSED
```

**`--timings` output (appended after normal output):**

```
=== Timings ===
graph load                1.23s
capability detect         0.08s
health scoring            4.51s  (24 modules, 10 workers)
  github API              3.92s  (48 calls)
  osv API                 0.59s  (24 calls)
output formatting         0.01s
────────────────────────────────────────
total                     5.83s
```

**`--json` adds:**
- `"graph_checksum"` — short SHA-256 of the dependency graph for diffing between CI runs

```bash
gorisk scan --json | jq .graph_checksum
```

**`--sarif`** produces SARIF 2.1.0 compatible with GitHub Code Scanning (rules GORISK001 = high-risk capability, GORISK002 = low health score).

**Exit codes:** 0 = passed, 1 = policy failure, 2 = error.

---

### `gorisk explain`

Show the *evidence* behind each capability detection — the exact file, line number, matched pattern, detection method, and confidence score.

```bash
# Show all capability evidence
gorisk explain

# Filter to a specific capability
gorisk explain --cap exec
gorisk explain --cap network
gorisk explain --cap unsafe

# Language-specific
gorisk explain --lang node

# JSON output (structured evidence for tooling)
gorisk explain --json
gorisk explain --cap exec --json
```

**Text output:**

```
=== Capability Evidence ===

exec
  github.com/foo/bar
    vendor/bar/run.go:42     exec.Command      [callSite  60%]
    vendor/bar/run.go:88     import "os/exec"  [import    90%]

network
  golang.org/x/net
    net/http.go:12           import "net/http"  [import   90%]
```

**`--json` output:** array of objects, one per `(package, capability)` pair:

```json
[
  {
    "package": "github.com/foo/bar",
    "module": "github.com/foo/bar",
    "capability": "exec",
    "evidence": [
      {
        "file": "/abs/path/run.go",
        "line": 42,
        "context": "exec.Command",
        "via": "callSite",
        "confidence": 0.6
      }
    ]
  }
]
```

**`via` values:**
- `import` — the capability was detected from an import statement (confidence: 0.90)
- `callSite` — detected from a function call pattern (confidence: 0.60)
- `installScript` — detected in `package.json` install scripts (confidence: 0.85)

---

### `gorisk capabilities`

List all packages and their detected capabilities with risk scores.

```bash
gorisk capabilities
gorisk capabilities --lang node
gorisk capabilities --lang go

# Filter by minimum risk level
gorisk capabilities --min-risk low       # show everything (default)
gorisk capabilities --min-risk medium    # MEDIUM and HIGH only
gorisk capabilities --min-risk high      # HIGH only

# JSON output
gorisk capabilities --json
```

**Text output:**

```
=== Capability Report ===

PACKAGE                          MODULE                           CAPABILITIES               SCORE  RISK
─────────────────────────────────────────────────────────────────────────────────────────────────────────
golang.org/x/net/http2           golang.org/x/net                 network                      15  MEDIUM
```

**Exit code:** 1 if any HIGH risk package was found (useful for `set -e` pipelines).

---

### `gorisk reachability`

Proves whether risky capabilities are **actually reachable** from your code — not just present in a transitive dependency.

- **Go**: SSA callgraph analysis (Rapid Type Analysis) from all `main()` and `init()` functions — resolves interprocedural call chains.
- **Node.js**: traces `require`/`import`/`import()` paths from project source files through the full dependency graph.
- **PHP**: traces `use` statements from project source files.
- **All other languages**: import-graph reachability — scans your source files for import/use/require statements and determines which packages from the lockfile are actually imported.

```bash
# Analyze all entrypoints
gorisk reachability
gorisk reachability --lang node

# Filter by minimum risk level
gorisk reachability --min-risk high     # only show HIGH risk packages
gorisk reachability --min-risk medium

# Target a specific binary (Go)
gorisk reachability --entry cmd/server/main.go
gorisk reachability --entry cmd/worker/main.go

# Target a specific entrypoint (Node.js)
gorisk reachability --entry src/app.ts
gorisk reachability --entry src/worker.js

# Combine flags
gorisk reachability --entry cmd/server/main.go --min-risk high
gorisk reachability --lang node --entry src/app.ts --json

# JSON output
gorisk reachability --json
```

**Text output:**

```
golang.org/x/net/http2                              HIGH    REACHABLE
  caps: network
os/exec                                             HIGH    unreachable
  caps: exec
```

- **REACHABLE** (coloured by risk) — the capability is exercised from your `main()` or entry file.
- **unreachable** (grey) — the package is in the graph but not called from your code.

**`--entry` use case:** In a monorepo with multiple binaries (`cmd/api`, `cmd/worker`, `cmd/cron`), each binary has a different reachable set. Targeting `cmd/api/main.go` shows only the capabilities reachable from the API service, helping you scope risk per binary.

**`--json` output:**

```json
[
  {
    "package": "golang.org/x/net/http2",
    "reachable": true,
    "risk": "HIGH",
    "score": 15,
    "capabilities": ["network"]
  }
]
```

---

### `gorisk graph`

Compute transitive risk scores across the full dependency tree. Uses depth-weighted scoring: `effective = direct + transitive/2` (capped at 100).

```bash
gorisk graph
gorisk graph --lang node

# Filter by minimum risk level
gorisk graph --min-risk medium
gorisk graph --min-risk high

# JSON output
gorisk graph --json
```

**Output columns:** Module | Direct score | Transitive score | Effective score | Depth | Risk level

---

### `gorisk diff`

Compare capabilities between two versions of a dependency. Detects **supply chain risk from capability escalation** — if an update quietly added `exec` or `network`, this catches it.

```bash
gorisk diff golang.org/x/net@v0.20.0 golang.org/x/net@v0.25.0
gorisk diff --lang node lodash@4.17.20 lodash@4.17.21
gorisk diff --json golang.org/x/net@v0.20.0 golang.org/x/net@v0.25.0
```

**Output:** per-package diff showing capabilities added (`+`) and removed (`-`).

**Exit codes:** 0 = no escalation, 1 = escalation detected (exec/network/unsafe/plugin added).

---

### `gorisk upgrade`

Check for breaking API changes before upgrading a dependency. Diffs exported function signatures between the current and target version.

```bash
gorisk upgrade golang.org/x/tools@v0.29.0
gorisk upgrade --lang node express@5.0.0
gorisk upgrade --json golang.org/x/tools@v0.29.0
```

**Output:** list of breaking changes (removed symbols, signature changes) and new transitive dependencies introduced by the upgrade.

---

### `gorisk impact`

Simulate removing a module and compute its **blast radius** — how many packages and binaries depend on it, and how many lines of code are transitively affected.

```bash
gorisk impact golang.org/x/tools
gorisk impact golang.org/x/tools@v0.29.0   # specific version
gorisk impact --json golang.org/x/tools
gorisk impact --lang node lodash
```

**Output:**

```
=== Blast Radius Report ===

Module:            golang.org/x/tools
Affected Packages: 42
Affected Binaries: 3
LOC Touched:       18200
Max Graph Depth:   5

Affected Binaries:
  cmd/gorisk/main.go
  cmd/scanner/main.go
  cmd/indexer/main.go
```

---

### `gorisk sbom`

Export a **CycloneDX 1.4 SBOM** with gorisk-specific extensions: capabilities per component, health score, and risk level.

```bash
gorisk sbom > sbom.json
gorisk sbom --lang node > sbom.json
gorisk sbom --format cyclonedx > sbom.json
```

Integrates with enterprise security platforms (Dependency-Track, FOSSA, etc.).

---

### `gorisk licenses`

Detect license risk across all dependencies via GitHub API. Flags copyleft and unknown licenses.

```bash
gorisk licenses
gorisk licenses --lang node
gorisk licenses --json

# Fail pipeline if risky licenses found
gorisk licenses --fail-on-risky
```

**Risky licenses** (exit 1 with `--fail-on-risky`): GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, LGPL-3.0, and `unknown`.

---

### `gorisk viz`

Generate an **interactive dependency risk graph** as a single self-contained HTML file. No server required — works offline and is shareable by email or as a PR comment attachment.

```bash
gorisk viz > graph.html
gorisk viz --min-risk medium > graph.html
gorisk viz --lang node > graph.html
open graph.html

# Export formats
gorisk viz --format html > graph.html    # default: interactive D3 graph
gorisk viz --format json > graph.json    # D3 node-link JSON (nodes + links arrays)
gorisk viz --format dot  > graph.dot     # Graphviz DOT (pipe to dot -Tsvg)
```

**Graph features:**
- Nodes coloured by risk — 🔴 HIGH ≥ 30 · 🟡 MEDIUM ≥ 10 · 🟢 LOW < 10
- Node size scales with risk score
- Hover a node to see its capabilities, score, file count, and import counts, with its edges highlighted
- **Click a node** to enter focus mode — neighbours animate into a ring around it, everything else dims; click again or empty space to exit
- **Blast radius mode** — highlights everything that depends on a clicked node (reverse reachability BFS)
- **Path finder mode** — click source then target to highlight the shortest dependency path
- **Module cluster hulls** — convex hulls group packages by module for visual organisation
- **Capability filter** — chip buttons to show only packages with specific capabilities (exec, network, fs:write, …)
- **Dark mode** — toggle in the settings panel (⚙)
- Filter by risk level using the chip buttons in the header
- Toggle edge visibility; edges shown faintly by default (hidden for very large graphs)
- Search packages by name or module
- Scroll to zoom, drag to pan, drag a node to pin it, double-click to unpin
- Reset button (⊙) zooms to fit all nodes

Large graphs (> 300 packages) use a phyllotaxis initial layout and freeze physics after settling to prevent jitter.

---

### `gorisk pr`

Detects dependency changes between two git refs and reports new capabilities, capability escalation, and removed modules. Designed for **pull request checks**.

```bash
gorisk pr                                # diffs origin/main...HEAD
gorisk pr --lang node
gorisk pr --base origin/main --head HEAD
gorisk pr --json

# Post a risk summary table as a PR comment (requires GITHUB_TOKEN + GORISK_PR_URL env vars)
gorisk pr --comment
```

**Exit code:** 1 if a new HIGH risk dependency was introduced (ideal as a CI gate on PRs).

---

### `gorisk history`

Track dependency risk over time. Snapshots are stored in `.gorisk-history.json` (add to `.gitignore`). Up to 100 snapshots are retained.

#### `gorisk history record`

Snapshot the current risk state.

```bash
gorisk history record
gorisk history record --lang node
gorisk history record --lang go
```

Captures: timestamp, git commit hash, all modules with risk level, effective score, and capabilities.

#### `gorisk history show`

List all recorded snapshots with a **trend column** showing how HIGH-risk module count changed from the previous snapshot.

```bash
gorisk history show
gorisk history show --json
```

**Text output:**

```
#     TIMESTAMP                  COMMIT        MODULES   HIGH  MEDIUM    LOW  TREND
──────────────────────────────────────────────────────────────────────────────────────
1     2026-01-01T10:00:00Z       a1b2c3d           12      2       4      6  —
2     2026-01-15T14:22:11Z       f4e5d6c           13      3       5      5  ↑ +1H
3     2026-02-01T09:45:30Z       9a8b7c6           13      2       5      6  ↓ -1H
```

**TREND column:**
- `—` — first snapshot or no HIGH-risk change from previous
- `↑ +NH` (red) — HIGH-risk module count increased by N
- `↓ -NH` (green) — HIGH-risk module count decreased by N
- `→` (grey) — same HIGH count, no change

#### `gorisk history diff`

Diff two snapshots to see what changed between them.

```bash
gorisk history diff              # diff the last two snapshots
gorisk history diff N            # diff snapshot N vs the latest
gorisk history diff N M          # diff snapshot N vs snapshot M
gorisk history diff --json       # JSON output
```

**Text output:**

```
drift  2026-01-01T10:00:00Z → 2026-02-01T09:45:30Z

  +  github.com/some/new-dep                             MEDIUM
  -  github.com/old/removed-dep
  ↑  github.com/escalated/dep                LOW → HIGH
  ↓  github.com/improved/dep                HIGH → MEDIUM

  added=1  removed=1  escalated=1  improved=1
```

**Change types:**
- `+` — new module (not in previous snapshot)
- `-` — removed module
- `↑` — risk escalated (higher risk level or higher effective score)
- `↓` — risk improved (lower risk level or lower effective score)

#### `gorisk history trend`

Per-module score **sparkline table** showing how each module's effective risk score has evolved across the last 10 snapshots.

```bash
gorisk history trend
gorisk history trend --module redis          # filter by module name substring
gorisk history trend --json
```

**Text output:**

```
MODULE                              TREND (last 10)       FIRST  LAST  CHANGE
────────────────────────────────────────────────────────────────────────────────
github.com/redis/go-redis           ▁▂▂▃▃▃▅▆▆▇              12    45    +33  ↑
github.com/stretchr/testify         ████████████              8     8      0  →
golang.org/x/net                    ▃▃▂▂▂▁▁▁▁▁              30    10    -20  ↓
```

**Sparkline:** 8 unicode block characters `▁▂▃▄▅▆▇█` represent score bands from 0–100.

**`--json` output:**

```json
[
  {
    "module": "github.com/redis/go-redis",
    "scores": [12, 18, 18, 24, 24, 24, 35, 40, 40, 45],
    "first_score": 12,
    "last_score": 45,
    "change": 33
  }
]
```

---

### `gorisk trace`

Runtime execution tracing — instruments a Go package and records which capabilities are exercised at runtime (as opposed to statically detected).

```bash
gorisk trace <package> [args...]
gorisk trace --timeout 10s github.com/foo/bar
gorisk trace --json github.com/foo/bar
```

---

### `gorisk init`

Generate a `.gorisk-policy.json` template in the current directory.

```bash
gorisk init                  # write .gorisk-policy.json
gorisk init --force          # overwrite existing file
gorisk init --stdout         # print to stdout without writing
gorisk init --with-hook      # also install .git/hooks/pre-commit
```

---

### `gorisk validate-policy`

Validate a policy file's JSON schema without running a full scan. Reports unknown fields with nearest-match suggestions.

```bash
gorisk validate-policy .gorisk-policy.json
```

**Exit codes:** 0 = valid, 1 = invalid, 2 = error.

---

### `gorisk plugins`

Manage gorisk capability detector and risk scorer plugins (stored in `~/.gorisk/plugins/`).

```bash
gorisk plugins list
gorisk plugins install /path/to/plugin.so
gorisk plugins install /path/to/plugin.so --force   # overwrite existing
gorisk plugins remove plugin.so
```

---

### `gorisk serve`

Start a local REST API server for programmatic access.

```bash
gorisk serve                 # listens on 127.0.0.1:8080
gorisk serve --port 9000
gorisk serve --host 0.0.0.0
```

**Endpoints:**

```bash
# Health check
curl http://localhost:8080/health
# → {"status":"ok"}

# Run a scan
curl -s -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"dir":"/path/to/project","lang":"auto"}' | jq .
```

Response HTTP status 200 = scan passed, 422 = scan failed policy.

---

### `gorisk version`

Print the gorisk version string.

```bash
gorisk version
```

---

## Policy file

gorisk can enforce rules automatically via a JSON policy file. Unknown fields are rejected at parse time.

```json
{
  "version": 1,
  "fail_on": "high",
  "confidence_threshold": 0.65,
  "min_health_score": 0,
  "max_health_score": 30,
  "block_archived": false,
  "deny_capabilities": ["exec", "plugin"],
  "allow_exceptions": [
    {
      "package": "github.com/my/tool",
      "capabilities": ["exec"],
      "expires": "2026-12-31"
    }
  ],
  "max_dep_depth": 0,
  "exclude_packages": [
    "github.com/myorg/*",
    "golang.org/x/*"
  ],
  "suppress": {
    "by_file_pattern": ["*_test.go", "testdata/**"],
    "by_module": ["github.com/test/*"],
    "by_capability_via": []
  }
}
```

Generate a template with `gorisk init` and validate with `gorisk validate-policy`.

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Schema version — currently `1`. |
| `fail_on` | string | Fail threshold: `"low"`, `"medium"`, or `"high"` (default: `"high"`) |
| `confidence_threshold` | float | Minimum evidence confidence (0.0–1.0). Recommended: `0.65`. Default: `0.0` (no filter). |
| `min_health_score` | int | Fail if any module's health score is below this (0 = disabled, `--online` only) |
| `max_health_score` | int | Fail if any module's health score is above this (0 = disabled, `--online` only) |
| `block_archived` | bool | Fail if any dependency is archived on GitHub (`--online` only) |
| `deny_capabilities` | []string | Block any package with these capabilities (e.g. `["exec", "network"]`) |
| `allow_exceptions` | []object | Per-package exemptions from `deny_capabilities`. Supports `expires` (ISO 8601 date). |
| `max_dep_depth` | int | Maximum allowed dependency depth (0 = unlimited) |
| `exclude_packages` | []string | Packages to skip entirely. Supports `/*` suffix for prefix matching. |
| `suppress` | object | Additional suppression: `by_file_pattern`, `by_module`, `by_capability_via` |

**allow_exceptions schema:**

```json
{
  "package": "github.com/my/tool",
  "capabilities": ["exec", "network"],
  "taint": ["env→exec"],
  "expires": "2026-12-31"
}
```

---

## Graph checksum

Every `gorisk scan` computes a short, deterministic SHA-256 digest of the dependency graph:

```
graph checksum: a3f2b1c9d5e78f01
```

The checksum covers: all non-main module paths and versions, all package import paths, capability sets, and dependency edges — all sorted for stability across runs.

**Use case:** Detect silent graph changes between CI runs without diffing full output:

```bash
# Run on main
gorisk scan --json | jq -r .graph_checksum > checksum-main.txt

# Run on PR branch
gorisk scan --json | jq -r .graph_checksum > checksum-pr.txt

# Alert if different
diff checksum-main.txt checksum-pr.txt && echo "graph unchanged" || echo "graph changed!"
```

---

## CI integration

### GitHub Actions (official action)

```yaml
- uses: 1homsi/gorisk@main
  with:
    fail-on: high          # low | medium | high (default: high)
    sarif: true            # upload to GitHub Security tab (default: true)
    lang: auto             # auto | go | node (default: auto)
    policy-file: ''        # optional path to policy.json
```

### Manual SARIF upload (GitHub Code Scanning)

```yaml
- name: gorisk scan
  run: gorisk scan --sarif --lang auto > gorisk.sarif || true

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: gorisk.sarif
```

### PR gate (GitHub Actions)

```yaml
- name: gorisk PR check
  run: gorisk pr --lang auto
```

### Full CI pipeline example

```yaml
name: gorisk
on: [push, pull_request]

jobs:
  gorisk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: stable }

      - name: Install gorisk
        run: go install github.com/1homsi/gorisk/cmd/gorisk@latest

      - name: Scan with policy
        run: gorisk scan --policy .gorisk-policy.json --sarif > gorisk.sarif

      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: gorisk.sarif

      - name: Record history snapshot
        run: gorisk history record

      - name: PR capability diff
        if: github.event_name == 'pull_request'
        run: gorisk pr
```

---

## Output formats

All commands that produce structured output support `--json`. The `gorisk scan` command additionally supports `--sarif`.

### `gorisk scan --json`

```json
{
  "graph_checksum": "a3f2b1c9d5e78f01",
  "Capabilities": [
    {
      "Package": "golang.org/x/net/http2",
      "Module": "golang.org/x/net",
      "Capabilities": { "Score": 15 },
      "RiskLevel": "MEDIUM"
    }
  ],
  "Health": [
    {
      "Module": "golang.org/x/net",
      "Version": "v0.25.0",
      "Score": 85,
      "Archived": false,
      "CVECount": 0,
      "CVEs": null,
      "Signals": { "release_frequency": 15, "commit_age": 0 }
    }
  ],
  "Passed": true,
  "FailReason": ""
}
```

### `gorisk explain --json`

```json
[
  {
    "package": "golang.org/x/net/http2",
    "module": "golang.org/x/net",
    "capability": "network",
    "evidence": [
      {
        "file": "/path/to/h2_bundle.go",
        "line": 47,
        "context": "import \"net\"",
        "via": "import",
        "confidence": 0.9
      }
    ]
  }
]
```

### `gorisk reachability --json`

```json
[
  {
    "package": "golang.org/x/net/http2",
    "reachable": true,
    "risk": "HIGH",
    "score": 15,
    "capabilities": ["network"]
  }
]
```

### `gorisk history trend --json`

```json
[
  {
    "module": "github.com/redis/go-redis",
    "scores": [12, 18, 24, 30, 45],
    "first_score": 12,
    "last_score": 45,
    "change": 33
  }
]
```

---

## Environment variables

| Variable | Purpose |
|----------|---------|
| `GORISK_GITHUB_TOKEN` | GitHub personal access token for health scoring (5000 req/hr vs 60 without) |
| `GORISK_FAIL_ON` | Override `fail_on` policy field at runtime (`low`, `medium`, `high`) |
| `GORISK_CONFIDENCE_THRESHOLD` | Override `confidence_threshold` at runtime (e.g. `0.65`) |
| `GORISK_ONLINE` | Set to `1` to enable health/CVE scoring without `--online` flag |
| `GORISK_LANG` | Force language detection (e.g. `go`, `node`, `python`) |
| `GITHUB_TOKEN` | Used by `gorisk pr --comment` to post PR comments |
| `GORISK_PR_URL` | GitHub API URL for the PR (e.g. `https://api.github.com/repos/owner/repo/pulls/123`) — used with `gorisk pr --comment` |

---

## Go SDK

gorisk ships a stable public API at `pkg/gorisk` for embedding scans in Go programs.

```go
import "github.com/1homsi/gorisk/pkg/gorisk"

func checkDeps(dir string) error {
    p, _ := gorisk.LoadPolicy(".gorisk-policy.json")
    scanner := gorisk.NewScanner(gorisk.ScanOptions{
        Dir:    dir,
        Lang:   "auto",
        Policy: p,
    })
    result, err := scanner.Scan()
    if err != nil {
        return err
    }
    if !result.Passed {
        return fmt.Errorf("gorisk: %s", result.FailReason)
    }
    return nil
}
```

The `pkg/gorisk` API is stable and will not have breaking changes within a major version. Internal packages (`internal/`) are not part of the public API.

---

## Setup for development

```bash
git clone https://github.com/1homsi/gorisk
cd gorisk
make setup   # installs git hooks (runs golangci-lint on commit)
make build
make test
```

---

## Contributing

Adding a new language requires two steps. gorisk already ships 22 languages — use any existing adapter (e.g. `internal/adapters/ruby/`) as a reference.

### 1. Graph loader — `internal/adapters/<lang>/`

Four files:

| File | Purpose |
|------|---------|
| `adapter.go` | Implements `Analyzer` interface (`Name()` + `Load(dir)`) |
| `lockfile.go` | Parses the language's lockfile / manifest into a `*graph.DependencyGraph` |
| `capability.go` | Scans source files for capability patterns; returns `capability.CapabilitySet` |
| `<lang>_test.go` | Unit tests — lockfile parsing + capability detection |

Register in `internal/analyzer/analyzer.go` → `ForLang()` switch + `detect()` + `registry` map.

To record capability evidence:

```go
cs.AddWithEvidence(capability.CapExec, capability.CapabilityEvidence{
    File:       filePath,
    Line:       lineNo,
    Context:    "subprocess.run(",
    Via:        "callSite",
    Confidence: 0.75,
})
```

### 2. Feature implementations

One file each in three packages:

| File | Interface | What it does |
|------|-----------|--------------|
| `internal/upgrade/<lang>.go` | `Upgrader` + `CapDiffer` | Reads current version from lockfile; returns upgrade risk report |
| `internal/prdiff/<lang>.go` | `Differ` | Diffs the lockfile between two git refs; returns added/updated/removed packages |
| `internal/reachability/<lang>.go` | `Analyzer` | Scans source files for imports; matches against loaded packages |

Register all four in `internal/analyzer/analyzer.go`:

```go
"mylang": {
    Upgrade:      upgrade.MyLangUpgrader{},
    CapDiff:      upgrade.MyLangCapDiffer{},
    PRDiff:       prdiff.MyLangDiffer{},
    Reachability: reachability.MyLangAnalyzer{},
},
```

The capability taxonomy, scoring, all output formats, explain evidence, history tracking, policy enforcement, and CLI flags all work automatically.

### What's not yet implemented

The following features have full implementations only for **Go, Node.js, and PHP**. All other languages fall back to simpler (but still correct) alternatives:

| Feature | Go / Node / PHP | All other languages |
|---------|----------------|---------------------|
| **Capability detection** | Deep AST + interprocedural callgraph; traces `main()` → helper → dangerous call | Import-level + call-site pattern scanning within source files |
| **Upgrade analysis** | Symbol-level diff of exported API (Go: `go list -m`; Node: npm download) | Lockfile version comparison; no cross-version capability download |
| **Reachability** | Full callgraph (Go: SSA/RTA; Node: module graph BFS) | Import-graph: packages directly imported by your source files |
| **PR diff capabilities** | Downloads new package version and re-scans for capability changes | Reports package version changes only; no re-scan of new version |

Contributions welcome to bring any language to Full depth.
