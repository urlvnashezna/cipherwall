# Secret detection reference

## Pattern rules

| rule | example | severity |
|---|---|---|
| `aws_access_key` | `AKIAIOSFODNN7EXAMPLE` | critical |
| `github_token` | `ghp_...` | critical |
| `private_key_block` | `-----BEGIN RSA PRIVATE KEY-----` | critical |
| `slack_webhook` | `hooks.slack.com/services/...` | high |
| `stripe_key` | `sk_live_...` | high |
| `google_api_key` | `AIza...` | high |

## High-entropy detection

Strings >= `min_length` (default 16) with Shannon entropy >=
`entropy_threshold` (default 4.2) are flagged as possible secrets. Common
header-like words (authorization, content-type, ...) are ignored.

## Masking

Detected values are masked in output (`abcd....wxyz`) - full values never
appear in reports, logs, or SARIF output.

## False positives

Tune per project in `cipherwall.yaml`:

```yaml
secrets:
  entropy_threshold: 4.6   # raise for hex-heavy projects
  min_length: 20
```
