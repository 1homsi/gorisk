# False Positive Guide

This document lists known false-positive patterns in gorisk's capability detection
and explains how to suppress them.

## What is a False Positive?

A false positive occurs when gorisk reports a capability (e.g., `exec`, `network`)
for a package or file that does not actually exercise that capability at runtime.

## Common Sources of False Positives

### 1. Test files that simulate dangerous operations

Test suites often call `exec.Command` or `os.Setenv` to test infrastructure code,
not production logic.

**Pattern**: `*_test.go` files with exec/env calls.

**Suppression**:
```json
{
  "suppress": {
    "by_file_pattern": ["*_test.go", "testdata/**"]
  }
}
```

### 2. Vendor directories

Vendored code is scanned by default. If you trust your vendor directory:

```json
{
  "exclude_packages": ["vendor/**"]
}
```

### 3. Stub/mock packages

Some packages export stubs that implement an interface without actually calling
the underlying OS function (e.g., a mock `http.Client`).

**Suppression** (per-package):
```json
{
  "allow_exceptions": [
    {
      "package": "github.com/org/repo/internal/mocks",
      "capabilities": ["network", "exec"]
    }
  ]
}
```

### 4. Import-only false positives (Go)

gorisk assigns a 0.90 confidence to import statements and 0.75 to call-site
matches. A package that imports `net/http` but only uses it for `http.StatusOK`
constants will show `network` at import confidence.

**Mitigation**: Use `confidence_threshold` to filter low-evidence findings:

```json
{
  "confidence_threshold": 0.80
}
```

### 5. Dynamic capability patterns

Some call-site patterns can match variable names that happen to contain the
pattern string. For example, a local variable `myexec` could match `exec(`
patterns if the namespacing is not strict enough.

gorisk uses namespaced patterns (e.g., `child_process.exec(` not `exec(`) to
mitigate this. If you encounter such a false positive, please report it as an
issue so we can improve the pattern.

### 6. Transitive taint paths through safe intermediaries

The taint BFS may find a path `env → [safe_util] → exec` even if `safe_util`
sanitizes the env value before using it. gorisk uses confidence multipliers per
hop to reduce this noise, but false positives can still occur.

**Suppression** (taint-specific):
```json
{
  "allow_exceptions": [
    {
      "package": "github.com/org/repo/util",
      "taint": ["env→exec"]
    }
  ]
}
```

## Reporting False Positives

If you find a reproducible false positive in a well-known open-source package,
please open an issue at https://github.com/1homsi/gorisk/issues with:

1. The package name and version
2. The capability(ies) falsely reported
3. A minimal reproducer (or link to the relevant source file)
4. What the code actually does (why it is NOT a true positive)

We maintain a curated list of confirmed false positives and will add patterns to
the suppression list in future releases.

## Tuning Confidence Thresholds

| Threshold | Effect |
|---|---|
| 0.0 (default) | All findings shown; highest recall |
| 0.65 | Filter unconfirmed call-site matches; recommended for CI |
| 0.75 | Import-level evidence only; lowest false-positive rate |
| 0.90 | Only high-confidence import evidence; very conservative |

Set in `.gorisk-policy.json`:

```json
{
  "confidence_threshold": 0.65
}
```

Or at scan time:

```bash
gorisk scan --hide-low-confidence
```
