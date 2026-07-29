# Cipherwall usage

## Quick start

```bash
cipherwall scan ./my-repo
cipherwall scan . --format json
cipherwall init    # write cipherwall.yaml
```

## Scan targets

Cipherwall scans any directory tree:

- Secret detection: regex patterns + high-entropy strings
- Dependency checks: go.mod, package.json, requirements.txt (offline advisory DB)

## Output formats

| format | use case |
|---|---|
| `table` | terminal (default) |
| `json` | machine parsing / jq |
| `sarif` | GitHub code scanning |
| `csv` | spreadsheets |

## Exit codes

- `0` - no findings
- `1` - findings and `exit_nonzero_on_findings: true` (default)
- `2` - scan error

## CI

```yaml
- run: go install github.com/urlvnashezna/cipherwall@latest
- run: cipherwall scan . --format sarif > findings.sarif
```

## Exclusions

```yaml
scan:
  exclude:
    - "vendor/"
    - "node_modules/"
    - "*.lock"
```

## Pre-commit hook

```yaml
- repo: local
  hooks:
    - id: cipherwall
      name: cipherwall
      entry: cipherwall scan
      language: system
      types: [text]
```
