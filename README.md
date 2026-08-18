<div align="center">

# ⚔️ Cipherwall

**The repo security gate you run before you push.**

```text
┌─────────────────────────────────────────────────────┐
│  ██████╗██╗██████╗██╗  ██╗███████╗██████╗ ██╗    │
│ ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██║    │
│ ██║     ██║██████╔╝███████║█████╗  ██████╔╝██║    │
│ ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔═══╝ ╚═╝    │
│ ╚██████╗██║██║     ██║  ██║███████╗██║     ██╗    │
│  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝    │
└─────────────────────────────────────────────────────┘
```

[![Go](https://img.shields.io/badge/Go-1.21%2B-10b981?style=flat-square&logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981.svg?style=flat-square)](LICENSE)
[![Offline-first](https://img.shields.io/badge/offline-first-no%20network-065f46?style=flat-square)](docs/secrets.md)
[![SARIF](https://img.shields.io/badge/SARIF-code%20scanning-ready-10b981?style=flat-square)](docs/usage.md)
[![PRs](https://img.shields.io/badge/PRs-welcome-10b981.svg?style=flat-square)](CONTRIBUTING.md)

</div>

---

## 🔐 What Cipherwall is

A single **Go binary** that gates your repo before it ever ships — scanning for
**leaked credentials** and **known-vulnerable dependencies** in one command.
No accounts. No network calls. No excuses.

```bash
$ cipherwall scan ./my-repo

[CRITICAL] config/settings.yaml:1  possible credential leak
      AKIA....MPLE
[CRITICAL] .env:1  possible credential leak
      ghp_....23456

2 finding(s): 2 critical
```

## 🗡️ The two-layer defense

| Layer | What it catches |
|---|---|
| 🩸 **Secrets** | AWS keys · GitHub/GitLab tokens · Slack webhooks · Stripe keys · private keys · **high-entropy strings** |
| 🧬 **Dependencies** | go.mod · package.json · requirements.txt · Cargo.toml against a **bundled offline advisory DB** |

## ⚡ Fast. Local. Private.

- **Fully offline** — bundled advisory DB, zero network calls
- **Detected secrets are masked** in every output format (`AKIA....MPLE`) — never leaked twice
- **One static binary** — no runtime, no deps, works in CI, hooks, and air-gapped environments

## 🚀 Quick start

```bash
git clone https://github.com/urlvnashezna/cipherwall.git && cd cipherwall
go build -o bin/cipherwall ./cmd/cipherwall
cipherwall init                     # write cipherwall.yaml
cipherwall scan .                   # scan this very repo
```

<details open>
<summary><b>🧪 Output formats</b></summary>

```bash
cipherwall scan . --format json     # jq-ready
cipherwall scan . --format sarif    # GitHub code scanning
cipherwall scan . --format csv      # spreadsheets / audits
```

</details>

## ⚙️ Configuration

```yaml
scan:
  exclude: ["vendor/", "node_modules/", "*.lock"]
secrets:
  entropy_threshold: 4.2            # Shannon entropy cutoff
  min_length: 16                    # ignore short strings
dependencies:
  min_severity: high                # noise floor
output:
  format: table                     # table | json | sarif | csv
  exit_nonzero_on_findings: true    # CI-friendly
```

## 📁 Layout

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
└── docs/                 usage · secrets
```

## 📚 Docs

- [Usage & CI](docs/usage.md) — including the pre-commit hook recipe
- [Secret detection reference](docs/secrets.md) — every rule + tuning knobs

## 🛡️ License

[MIT](LICENSE) — do what you want, just don't blame us.

---

<div align="center">

*Scan before you ship.*

</div>
