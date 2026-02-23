# Policy File Reference

gorisk uses a `.gorisk-policy.json` file to configure scan enforcement. Generate
a template with `gorisk init`.

## Full Schema

```json
{
  "version": 1,
  "fail_on": "high",
  "confidence_threshold": 0.0,
  "deny_capabilities": [],
  "allow_exceptions": [],
  "exclude_packages": [],
  "max_dep_depth": 0,
  "suppress": {
    "by_file_pattern": [],
    "by_module": [],
    "by_capability_via": []
  },
  "max_health_score": 30,
  "min_health_score": 0,
  "block_archived": false
}
```

## Field Reference

### `version` (int)
Schema version. Currently only `1` is supported. Omit or set to `1`.

### `fail_on` (string)
Risk level at which `gorisk scan` exits with code 1.

| Value | Meaning |
|---|---|
| `"low"` | Fail on any finding |
| `"medium"` | Fail on MEDIUM or HIGH findings |
| `"high"` | Fail on HIGH findings only (default) |

Override at runtime: `gorisk scan --fail-on medium` or `GORISK_FAIL_ON=medium`.

### `confidence_threshold` (float, 0.0–1.0)
Minimum evidence confidence required to include a finding. Default `0.0` (no filter).

Recommended values:
- `0.65` — filter out low-confidence call-site regex matches
- `0.75` — import-level evidence only (Go AST)
- `0.90` — highest-confidence evidence only

Override: `gorisk scan --hide-low-confidence` sets `0.65`.
Override: `GORISK_CONFIDENCE_THRESHOLD=0.75`.

### `deny_capabilities` ([]string)
List of capabilities that are never allowed. `gorisk scan` will fail if any
non-excepted package uses a denied capability.

```json
{
  "deny_capabilities": ["exec", "unsafe"]
}
```

### `allow_exceptions` ([]PolicyException)
Per-package exceptions to capability or taint enforcement.

```json
{
  "allow_exceptions": [
    {
      "package": "github.com/pkg/sftp",
      "capabilities": ["network"],
      "expires": "2026-12-31"
    },
    {
      "package": "github.com/org/repo",
      "taint": ["env→exec"]
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `package` | string | Exact package import path |
| `capabilities` | []string | Capabilities to suppress for this package |
| `taint` | []string | Taint flow pairs to suppress (e.g. `"env→exec"`) |
| `expires` | string | ISO 8601 date. Exception is ignored after this date. |

### `exclude_packages` ([]string)
Packages to skip entirely (not scored, not reported). Supports `/*` suffix
for prefix matching.

```json
{
  "exclude_packages": [
    "github.com/myorg/*",
    "golang.org/x/*",
    "gopkg.in/yaml.v3"
  ]
}
```

### `max_dep_depth` (int)
Maximum transitive dependency depth to scan. `0` means unlimited.

### `suppress` (object)

Additional suppression rules that silence findings without removing packages.

| Field | Type | Description |
|---|---|---|
| `by_file_pattern` | []string | Suppress findings from files matching these patterns (e.g. `*_test.go`) |
| `by_module` | []string | Suppress findings from packages in these modules (supports `/*`) |
| `by_capability_via` | []string | Suppress findings where evidence `via` matches (e.g. `"import"`) |

### `max_health_score` (int, online only)
Maximum allowed health score. Packages scoring above this fail the scan.
Only evaluated when `--online` is passed.

### `min_health_score` (int, online only)
Minimum required health score. Packages scoring below this fail the scan.
Only evaluated when `--online` is passed.

### `block_archived` (bool, online only)
If `true`, any archived module fails the scan.

## Environment Variable Overrides

The following environment variables override policy settings at runtime:

| Variable | Policy field | Example |
|---|---|---|
| `GORISK_FAIL_ON` | `fail_on` | `GORISK_FAIL_ON=medium` |
| `GORISK_CONFIDENCE_THRESHOLD` | `confidence_threshold` | `GORISK_CONFIDENCE_THRESHOLD=0.65` |
| `GORISK_ONLINE` | enables `--online` | `GORISK_ONLINE=1` |
| `GORISK_LANG` | forces language | `GORISK_LANG=go` |

## Validation

Validate your policy file without running a full scan:

```bash
gorisk validate-policy .gorisk-policy.json
```

This checks JSON syntax, unknown fields (with nearest-match suggestions), and
`fail_on` value validity.
