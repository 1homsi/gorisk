# gorisk

<img src="assets/gorisk.png" alt="gorisk" width="480"/>

Polyglot dependency risk analyzer. Maps what your dependencies **can do**, not just what CVEs they have.

## Why gorisk

| Tool | CVEs | Capabilities | Upgrade risk | Blast radius | Polyglot | Offline | Free |
|------|------|-------------|--------------|-------------|----------|---------|------|
| govulncheck | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Snyk | ✅ | ❌ | partial | ❌ | partial | ❌ | SaaS |
| goda | ❌ | ❌ | ❌ | partial | ❌ | ✅ | ✅ |
| GoSurf | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **gorisk** | via OSV | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** |

Key differentiators:

- **Polyglot** — pluggable `Analyzer` interface means any language can be added. Ships with Go and Node.js today; Python, Rust, Java, and Ruby are on the roadmap.
- **Capability detection** — detect which packages can read files, make network calls, spawn processes, or use `unsafe`/`eval`. Know *what your dependencies can do* before they're in production.
- **Capability diff** — compare two versions of a dependency and detect capability escalation. If `v1.2.3 → v1.3.0` quietly added `exec` or `network`, gorisk flags it as a supply chain risk signal.
- **CVE listing** — full list of OSV vulnerability IDs per module, not just a count.
- **Blast radius** — simulate removing a module and see exactly which packages and binaries break, plus LOC impact.
- **Upgrade risk** — diff exported symbols between versions to detect breaking API changes before you upgrade.
- **Health scoring** — combines commit activity, release cadence, archived status, and CVE count into a single score.
- **CI-native** — SARIF output compatible with GitHub Code Scanning. Exit codes for policy gating.

## Install

```bash
go install github.com/1homsi/gorisk/cmd/gorisk@latest
```

## Language support

gorisk auto-detects the language from the project directory. Use `--lang` to override.

```bash
gorisk scan              # auto-detect
gorisk scan --lang go    # force Go
gorisk scan --lang node  # force Node.js
```

When both `go.mod` and `package.json` are present (monorepo), both analyzers run and their dependency graphs are merged.

### Supported languages

| Language | `--lang` | Status | Detection signal | Lockfile / manifest |
|----------|----------|--------|-----------------|---------------------|
| **Go** | `go` | ✅ stable | `go.mod` | `go.mod` + `go list` |
| **Node.js** | `node` | ✅ stable | `package.json` | `package-lock.json` v1/v2/v3, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `python` | 🗓 planned | `requirements.txt` / `pyproject.toml` | `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| Rust | `rust` | 🗓 planned | `Cargo.toml` | `Cargo.lock` |
| Java | `java` | 🗓 planned | `pom.xml` / `build.gradle` | Maven, Gradle lock files |
| Ruby | `ruby` | 🗓 planned | `Gemfile` | `Gemfile.lock` |

Want to add a language? The `Analyzer` interface is a single `Load(dir string) (*graph.DependencyGraph, error)` method — see [contributing](#contributing).

### Capability detection per language

#### Go
Detects capabilities via static AST analysis of `.go` source files:

| Import / call | Capabilities |
|--------------|--------------|
| `os`, `io/fs` | `fs:read`, `fs:write` |
| `net`, `net/http` | `network` |
| `os/exec` | `exec` |
| `os.Getenv` | `env` |
| `unsafe` | `unsafe` |
| `crypto/*` | `crypto` |
| `reflect` | `reflect` |
| `plugin` | `plugin` |

#### Node.js
Scans `.js`, `.ts`, `.tsx`, `.mjs`, `.cjs` files for `require()`, ESM `import`, and dynamic `import()` patterns:

| Import / call | Capabilities |
|--------------|--------------|
| `fs`, `node:fs`, `fs/promises` | `fs:read`, `fs:write` |
| `http`, `https`, `net`, `tls` | `network` |
| `child_process`, `worker_threads`, `cluster` | `exec` |
| `os`, `process` | `env` |
| `crypto` | `crypto` |
| `vm` | `unsafe` |
| `module`, dynamic `import()` | `plugin` |
| `eval(`, `new Function(` | `unsafe` |
| `exec(`, `spawn(`, `fork(` | `exec` |
| `fetch(`, `axios.`, `got(` | `network` |
| `readFile`, `writeFile`, `unlink(` | `fs:read` / `fs:write` |
| `process.env` | `env` |
| `preinstall`/`postinstall` with `curl`/`wget`/`bash` | `exec` + `network` |

### Capability taxonomy

All languages map to the same 9 capabilities:

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

Risk level is derived from the total weight: **LOW** < 10, **MEDIUM** ≥ 10, **HIGH** ≥ 30.

## Commands

### `gorisk scan`

Full scan: capabilities + health scoring + CVE listing + CI gate.

```bash
gorisk scan                              # auto-detect language
gorisk scan --lang node                  # Node.js project
gorisk scan --sarif > results.sarif
gorisk scan --fail-on medium
gorisk scan --policy policy.json
```

Output includes three tables:

1. **Capability Report** — package, module, detected capabilities, score, risk level
2. **Health Report** — module, version, health score, CVE count, status
3. **Vulnerabilities** — one row per OSV vulnerability ID (only shown when CVEs exist)

```
=== Vulnerabilities ===

MODULE                    VULNERABILITY ID
─────────────────────────────────────────────────────
golang.org/x/net          GO-2023-1571
golang.org/x/net          GHSA-4374-p667-p6c8
```

IDs link to `https://osv.dev/vulnerability/<ID>` for full details.

### `gorisk capabilities`

Detect what each package in your module can do.

```bash
gorisk capabilities                      # auto-detect language
gorisk capabilities --lang node
gorisk capabilities --min-risk high
gorisk capabilities --json
```

### `gorisk graph`

Compute transitive risk scores across the full dependency tree. Shows direct, transitive, and effective risk with depth-weighted scoring.

```bash
gorisk graph
gorisk graph --lang node
gorisk graph --min-risk medium
gorisk graph --json
```

Output columns: Module | Direct score | Transitive score | Effective score | Depth | Risk level

### `gorisk sbom`

Export a CycloneDX 1.4 SBOM with capabilities, health score, and risk level per component.

```bash
gorisk sbom > sbom.json
gorisk sbom --lang node > sbom.json
gorisk sbom --format cyclonedx
```

Integrates with enterprise security platforms (Dependency-Track, etc.).

### `gorisk licenses`

Detect license risk across dependencies via GitHub API.

```bash
gorisk licenses
gorisk licenses --lang node
gorisk licenses --fail-on-risky        # exit 1 if GPL/AGPL/unknown found
gorisk licenses --json
```

Flags risky licenses: GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, LGPL-3.0 and unknown licenses.

### `gorisk diff` ⚡ unique

Compare capabilities between two versions of a dependency. Detects supply chain risk from capability escalation.

```bash
gorisk diff golang.org/x/net@v0.20.0 golang.org/x/net@v0.25.0
gorisk diff --lang node lodash@4.17.20 lodash@4.17.21
```

Output flags capability additions/removals per package. Exit 1 if escalation detected (exec/network/unsafe/plugin added).

### `gorisk upgrade`

Check for breaking API changes before upgrading a dependency.

```bash
gorisk upgrade golang.org/x/tools@v0.29.0
gorisk upgrade --lang node express@5.0.0
```

### `gorisk impact`

Simulate removing a module and compute blast radius.

```bash
gorisk impact golang.org/x/tools
gorisk impact --json golang.org/x/tools
```

### `gorisk reachability` ⚡ unique

Determines whether risky capabilities are **actually reachable** — not just imported. For Go, uses callgraph analysis (RTA) from `main`. For Node.js, traces `require`/`import` paths from project source files.

```bash
gorisk reachability
gorisk reachability --lang node
gorisk reachability --min-risk high
gorisk reachability --json
```

### `gorisk pr`

Detects dependency changes between two git refs and reports new capabilities, capability escalation, and removed modules. Designed for PR checks.

```bash
gorisk pr                              # diffs origin/main...HEAD
gorisk pr --lang node
gorisk pr --base origin/main --head HEAD
gorisk pr --json
```

Exits 1 if a new HIGH risk dependency was introduced.

### Policy file

```json
{
  "fail_on": "high",
  "max_health_score": 30,
  "min_health_score": 0,
  "block_archived": false,
  "deny_capabilities": ["exec", "plugin"],
  "allow_exceptions": [
    { "package": "github.com/my/tool", "capabilities": ["exec"] }
  ],
  "max_dep_depth": 0,
  "exclude_packages": []
}
```

| Field | Description |
|-------|-------------|
| `fail_on` | Fail on risk level: `low`, `medium`, `high` |
| `max_health_score` | Fail if health score exceeds this (legacy) |
| `min_health_score` | Fail if health score is below this |
| `block_archived` | Fail if any dep is archived on GitHub |
| `deny_capabilities` | Block packages with these capabilities |
| `allow_exceptions` | Per-package exemptions for denied caps |
| `max_dep_depth` | Maximum allowed dependency depth (0 = unlimited) |
| `exclude_packages` | Packages to skip entirely |

## GitHub Action

```yaml
- uses: 1homsi/gorisk@main
  with:
    fail-on: high          # low | medium | high (default: high)
    sarif: true            # upload to GitHub Security tab (default: true)
    lang: auto             # auto | go | node (default: auto)
    policy-file: ''        # optional path to policy.json
```

### Manual CI integration

```yaml
- name: gorisk scan
  run: gorisk scan --sarif --lang auto > gorisk.sarif || true

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: gorisk.sarif
```

## Setup

```bash
git clone https://github.com/1homsi/gorisk
cd gorisk
make setup   # installs git hooks (runs golangci-lint on commit)
make build
make test
```

## Environment

| Variable | Purpose |
|----------|---------|
| `GORISK_GITHUB_TOKEN` | GitHub token for health scoring (higher rate limits) |

## Contributing

Adding a new language requires two steps:

### 1. Graph loader — `internal/adapters/<lang>/adapter.go`

Implement the `Analyzer` interface to build a dependency graph:

```go
type Analyzer interface {
    Name() string
    Load(dir string) (*graph.DependencyGraph, error)
}
```

Register it in `internal/analyzer/analyzer.go` → `ForLang()` switch and add a detection signal to `detect()`.

### 2. Feature implementations

Each feature package defines an interface + per-language structs. Implement them for the new language:

| Package | Interface | Example impl |
|---------|-----------|--------------|
| `internal/reachability` | `Analyzer` | `GoAnalyzer`, `NodeAnalyzer` |
| `internal/upgrade` | `Upgrader` | `GoUpgrader`, `NodeUpgrader` |
| `internal/upgrade` | `CapDiffer` | `GoCapDiffer`, `NodeCapDiffer` |
| `internal/prdiff` | `Differ` | `GoDiffer`, `NodeDiffer` |

Then add a single entry to the registry in `internal/analyzer/analyzer.go`:

```go
var registry = map[string]LangFeatures{
    "go":   { ... },
    "node": { ... },
    "rust": {  // your new entry
        Upgrade:      upgrade.RustUpgrader{},
        CapDiff:      upgrade.RustCapDiffer{},
        PRDiff:       prdiff.RustDiffer{},
        Reachability: reachability.RustAnalyzer{},
    },
}
```

The capability taxonomy, all output formats, and CLI flags come for free.
