<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rounded&height=180&color=0:134e4a,50:0f766e,100:14b8a6&text=Cipherwall&fontSize=56&fontColor=ffffff&animation=fadeIn&desc=secret%20and%20dependency%20scanner%20for%20your%20repos&descSize=17&descAlignY=64" width="100%" />

[![Go](https://img.shields.io/badge/Go-1.21%2B-14b8a6?style=for-the-badge&logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/License-MIT-134e4a?style=for-the-badge)](LICENSE)
[![Offline](https://img.shields.io/badge/offline-first-advisory%20db-14b8a6?style=for-the-badge)](docs/secrets.md)
[![SARIF](https://img.shields.io/badge/SARIF-code%20scanning-134e4a?style=for-the-badge)](docs/usage.md)

</div>

---

## 🔒 What Cipherwall is

A **Go binary** that scans a repository for leaked credentials and vulnerable
dependencies — locally, in CI, or as a pre-commit hook.

```bash
cipherwall scan ./my-repo
[CRITICAL] config/settings.yaml:1  possible credential leak
      AKIA....MPLE
[CRITICAL] .env:1  possible credential leak
      ghp_....23456

2 finding(s): 2 critical
```

## 🛡️ What it detects

| layer | catches |
|---|---|
| **Secrets** | AWS keys, GitHub tokens, Slack webhooks, private keys, Stripe keys + high-entropy strings |
| **Dependencies** | go.mod / package.json / requirements.txt against a bundled offline advisory DB |

## ⚡ Why

Leaked keys and known-vulnerable deps are the two most common ways repos get
compromised. Cipherwall makes both checks a one-command habit — and it runs
**fully offline** (no API calls, no telemetry, no accounts).

## 🚀 Quick start

```bash
git clone https://github.com/urlvnashezna/cipherwall.git && cd cipherwall
go build -o bin/cipherwall ./cmd/cipherwall
cipherwall init                       # write cipherwall.yaml
cipherwall scan .                     # scan this repo
```

<details open>
<summary><b>👀 Formats & CI</b></summary>

```bash
cipherwall scan . --format json      # machine-readable
cipherwall scan . --format sarif     # GitHub code scanning
cipherwall scan . --format csv       # spreadsheets

# CI
- run: cipherwall scan . --format sarif > findings.sarif
```

</details>

## ⚙️ Config

```yaml
scan:
  exclude: ["vendor/", "node_modules/", "*.lock"]
secrets:
  entropy_threshold: 4.2
  min_length: 16
dependencies:
  min_severity: high
output:
  format: table
  exit_nonzero_on_findings: true
```

## 📁 Repo layout

```text
.
├── cmd/cipherwall/       entrypoint
├── internal/
│   ├── cli/              cobra command surface
│   ├── config/           cipherwall.yaml load/validate
│   ├── scanner/          regex + entropy secret detection
│   ├── deps/             manifest scanning + advisory DB
│   ├── finding/          findings model + severity
│   └── output/           table · json · sarif · csv
├── config.example.yaml
├── go.mod
├── Makefile
├── CHANGELOG.md
└── docs/                 usage · secrets
```

## 📚 Docs

- [Usage & CI](docs/usage.md)
- [Secret detection reference](docs/secrets.md)

## 🛡️ License

MIT. See `LICENSE`.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rounded&height=80&color=0:14b8a6,50:0f766e,100:134e4a&section=footer" width="100%" />

*Scan before you ship.*

</div>

> **Tip:** run `cipherwall scan . --format sarif` in CI and upload the result to GitHub code scanning - no action needed on your side beyond the upload step.
