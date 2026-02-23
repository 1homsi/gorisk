# CI Integration Examples

## GitHub Actions

### Basic scan (fail on HIGH)

```yaml
name: gorisk scan
on: [push, pull_request]

jobs:
  gorisk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 1homsi/gorisk-action@v1
        with:
          fail-on: high
```

### With policy file

```yaml
      - uses: 1homsi/gorisk-action@v1
        with:
          policy-file: .gorisk-policy.json
          sarif-output: gorisk.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gorisk.sarif
```

### PR diff scanning

```yaml
name: gorisk pr diff
on: [pull_request]

jobs:
  gorisk-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go install github.com/1homsi/gorisk/cmd/gorisk@latest
      - run: gorisk pr --base ${{ github.event.pull_request.base.sha }}
```

## GitLab CI

```yaml
gorisk:
  stage: test
  image: golang:1.25
  script:
    - go install github.com/1homsi/gorisk/cmd/gorisk@latest
    - gorisk scan --fail-on high --policy .gorisk-policy.json
  artifacts:
    reports:
      sast: gorisk.sarif
    when: always
  allow_failure: false
```

## CircleCI

```yaml
version: 2.1
jobs:
  gorisk:
    docker:
      - image: golang:1.25
    steps:
      - checkout
      - run:
          name: Install gorisk
          command: go install github.com/1homsi/gorisk/cmd/gorisk@latest
      - run:
          name: Run gorisk scan
          command: gorisk scan --fail-on high
```

## Pre-commit Hook

Generate a pre-commit hook with:

```bash
gorisk init --with-hook
```

This writes `.git/hooks/pre-commit`:

```bash
#!/bin/sh
gorisk scan --fail-on high --policy .gorisk-policy.json 2>&1
```

Or install manually:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
gorisk scan --fail-on high 2>&1
EOF
chmod +x .git/hooks/pre-commit
```

## Programmatic Usage (Go SDK)

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

## REST API

Start the server:

```bash
gorisk serve --port 8080
```

Trigger a scan:

```bash
curl -s -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"dir":"/path/to/project","lang":"go"}' | jq .
```

Health check:

```bash
curl -s http://localhost:8080/health
# {"status":"ok"}
```

## Environment Variables in CI

All policy settings can be overridden via environment variables, useful for
CI pipelines where modifying the policy file is impractical:

```yaml
env:
  GORISK_FAIL_ON: medium
  GORISK_CONFIDENCE_THRESHOLD: "0.65"
  GORISK_ONLINE: "1"  # enable health/CVE scoring
```
