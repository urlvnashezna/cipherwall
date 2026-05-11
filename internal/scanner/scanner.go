// Package scanner implements secret detection.
//
// Detection is two-layered:
//   1. Regex patterns for known credential formats (AWS keys, GitHub tokens,
//      Slack webhooks, private keys, ...).
//   2. High-entropy string detection for anything that looks like a random
//      secret even when we don't have a pattern for it.
package scanner

import (
	"bufio"
	"bytes"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/urlvnashezna/cipherwall/internal/config"
	"github.com/urlvnashezna/cipherwall/internal/finding"
)

// Scanner runs secret detection over a tree.
type Scanner struct {
	cfg      *config.Config
	patterns []*regexp.Regexp
}

// New builds a Scanner from config.
func New(cfg *config.Config) (*Scanner, error) {
	s := &Scanner{cfg: cfg}
	for _, name := range cfg.Secrets.Patterns {
		re, ok := patterns[name]
		if !ok {
			continue
		}
		s.patterns = append(s.patterns, re)
	}
	return s, nil
}

// patterns maps rule names to compiled regexes.
var patterns = map[string]*regexp.Regexp{
	"aws_access_key": regexp.MustCompile(
		`AKIA[0-9A-Z]{16}`),
	"github_token": regexp.MustCompile(
		`gh[pousr]_[A-Za-z0-9]{36,}`),
	"slack_webhook": regexp.MustCompile(
		`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
	"private_key_block": regexp.MustCompile(
		`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	"google_api_key": regexp.MustCompile(
		`AIza[0-9A-Za-z\-_]{35}`),
	"stripe_key": regexp.MustCompile(
		`sk_live_[0-9a-zA-Z]{24,}`),
}

// entropy returns the Shannon entropy of a string.
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ScanSecrets walks target and returns findings.
func (s *Scanner) ScanSecrets(target string) ([]finding.Finding, error) {
	if !s.cfg.Secrets.Enabled {
		return nil, nil
	}
	var findingsOut []finding.Finding
	maxBytes := s.cfg.Scan.MaxFileSizeMB * 1024 * 1024

	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable
		}
		if d.IsDir() {
			for _, ex := range s.cfg.Scan.Exclude {
				if strings.HasPrefix(path, ex) || strings.Contains(path, ex) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		rel := path
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > int64(maxBytes) {
			return nil
		}
		fs, err := s.scanFile(rel, info)
		if err == nil {
			findingsOut = append(findingsOut, fs...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	finding.Sort(findingsOut)
	return findingsOut, nil
}

func (s *Scanner) scanFile(path string, info fs.FileInfo) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []finding.Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		for rule, re := range patterns {
			locs := re.FindAllIndex(line, -1)
			for _, loc := range locs {
				out = append(out, finding.Finding{
					Kind: "secret", RuleID: rule,
					Severity: severityFor(rule),
					File: path, Line: lineNo,
					Column: loc[0] + 1,
					Message: "possible credential leak",
					Value:   maskSecret(string(line[loc[0]:loc[1]])),
				})
			}
		}
		if s.cfg.Secrets.EntropyThreshold > 0 {
			for _, token := range strings.Fields(string(line)) {
				token = strings.Trim(token, `"'=,;:`)
				if len(token) >= s.cfg.Secrets.MinLength &&
					entropy(token) >= s.cfg.Secrets.EntropyThreshold &&
					looksRandom(token) {
					out = append(out, finding.Finding{
						Kind: "secret", RuleID: "high-entropy",
						Severity: finding.SeverityMedium,
						File: path, Line: lineNo,
						Message: "high-entropy string (possible secret)",
						Value:   maskSecret(token),
					})
				}
			}
		}
	}
	return out, nil
}

func severityFor(rule string) finding.Severity {
	switch rule {
	case "aws_access_key", "github_token", "private_key_block":
		return finding.SeverityCritical
	case "slack_webhook", "stripe_key":
		return finding.SeverityHigh
	}
	return finding.SeverityMedium
}

// maskSecret keeps only the first and last 4 characters.
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// looksRandom rejects obvious words (keys like "authorization" etc).
func looksRandom(s string) bool {
	if bytes.EqualFold([]byte(s), []byte("authorization")) {
		return false
	}
	for _, w := range commonWords {
		if strings.EqualFold(s, w) {
			return false
		}
	}
	return true
}

var commonWords = []string{
	"authorization", "authentication", "content-type", "user-agent",
	"application/json", "x-api-key", "x-auth-token",
}

	"gitlab_token": regexp.MustCompile(
		`glpat-[A-Za-z0-9_-]{20,}`),
