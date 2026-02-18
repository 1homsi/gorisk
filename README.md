# gorisk

<img src="assets/gorisk.png" alt="gorisk" width="480"/>

Polyglot dependency risk analyzer. Maps what your dependencies **can do**, not just what CVEs they have. Supports Go and Node.js projects out of the box.

## Why gorisk

| Tool | CVEs | Capabilities | Upgrade risk | Blast radius | Node.js | Offline | Free |
|------|------|-------------|--------------|-------------|---------|---------|------|
| govulncheck | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Snyk | ✅ | ❌ | partial | ❌ | ✅ | ❌ | SaaS |
| goda | ❌ | ❌ | ❌ | partial | ❌ | ✅ | ✅ |
| GoSurf | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **gorisk** | via OSV | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** |

Key differentiators:

- **Polyglot** — supports Go (`go.mod`) and Node.js (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) out of the box. Auto-detects the language; monorepos with both run both analyzers and merge results.
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

gorisk auto-detects the language from the project directory:

| Signal | Analyzer |
|--------|----------|
| `go.mod` | Go — static AST analysis via `go list` |
| `package-lock.json` | Node.js — npm lockfile v1/v2/v3 |
| `yarn.lock` | Node.js — Yarn classic lockfile |
| `pnpm-lock.yaml` | Node.js — pnpm lockfile v6/v9 |
| both `go.mod` + `package.json` | Both analyzers run, graphs merged |

Override with `--lang`:

```bash
gorisk scan --lang go      # force Go analyzer
gorisk scan --lang node    # force Node.js analyzer
gorisk scan --lang auto    # default: auto-detect
```

Node.js capability detection scans `.js`, `.ts`, `.tsx`, `.mjs`, `.cjs` files for:
- `require()` / ESM `import` / dynamic `import()` calls → maps built-in modules to capabilities
- Call-site patterns: `exec(`, `spawn(`, `eval(`, `readFile`, `writeFile`, `fetch(`, etc.
- `preinstall`/`postinstall` scripts containing `curl`, `wget`, `bash` → flags `exec` + `network`

## Commands

### `gorisk capabilities`

Detect what each package in your module can do.

```bash
gorisk capabilities                      # auto-detect language
gorisk capabilities --lang node          # Node.js project
gorisk capabilities --min-risk high
gorisk capabilities --json
```

### `gorisk diff` ⚡ unique

Compare capabilities between two versions of a dependency. Detects supply chain risk from capability escalation.

```bash
gorisk diff golang.org/x/net@v0.20.0 golang.org/x/net@v0.25.0
```

Output flags capability additions/removals per package. Exit 1 if escalation detected (exec/network/unsafe/plugin added).

### `gorisk upgrade`

Check for breaking API changes before upgrading a dependency.

```bash
gorisk upgrade golang.org/x/tools@v0.29.0
```

### `gorisk impact`

Simulate removing a module and compute blast radius.

```bash
gorisk impact golang.org/x/tools
gorisk impact --json golang.org/x/tools
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

### `gorisk reachability` ⚡ unique

Uses callgraph analysis (RTA) to determine whether risky capabilities are **actually reachable** from your `main` functions — not just imported. Eliminates false positives.

```bash
gorisk reachability ./...
gorisk reachability --min-risk high ./...
gorisk reachability --json ./...
```

### `gorisk pr`

Detects dependency changes between two git refs and reports new capabilities, capability escalation, and removed modules. Designed for PR checks.

```bash
gorisk pr                              # diffs origin/main...HEAD
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
