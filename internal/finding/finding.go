// Package finding models a single scan result.
package finding

import (
	"fmt"
	"sort"
	"strings"
)

// Severity levels for both secret and dependency findings.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// ParseSeverity converts a string to a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	}
	return SeverityInfo, fmt.Errorf("unknown severity %q", s)
}

// Finding is one scan result.
type Finding struct {
	Kind     string   `json:"kind"`     // secret | dependency
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Message  string   `json:"message"`
	Value    string   `json:"value,omitempty"`
}

// Sort orders findings by severity desc, then file/line.
func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// CountBySeverity summarizes findings.
func CountBySeverity(fs []Finding) map[Severity]int {
	out := map[Severity]int{}
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}

// Fingerprint returns a stable dedup key for a finding.
func (f Finding) Fingerprint() string {
	return fmt.Sprintf("%s:%s:%d", f.Kind, f.File, f.Line)
}
