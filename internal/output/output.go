// Package output renders findings in table/json/sarif/csv form.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/urlvnashezna/cipherwall/internal/finding"
)

// Renderer writes findings in a chosen format.
type Renderer struct {
	format string
	color  bool
	out    io.Writer
}

// New builds a renderer.
func New(format, colorMode string) (*Renderer, error) {
	useColor := colorMode == "always"
	if colorMode == "auto" {
		useColor = isTTY(os.Stdout)
	}
	return &Renderer{format: format, color: useColor, out: os.Stdout}, nil
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Render writes all findings.
func (r *Renderer) Render(fs []finding.Finding, target string) {
	finding.Sort(fs)
	switch r.format {
	case "json":
		r.renderJSON(fs)
	case "sarif":
		r.renderSARIF(fs)
	case "csv":
		r.renderCSV(fs)
	default:
		r.renderTable(fs, target)
	}
}

func (r *Renderer) renderTable(fs []finding.Finding, target string) {
	if len(fs) == 0 {
		fmt.Fprintf(r.out, "cipherwall: no findings in %s
", target)
		return
	}
	for _, f := range fs {
		sev := f.Severity.String()
		if r.color {
			sev = colorSeverity(f.Severity, sev)
		}
		fmt.Fprintf(r.out, "[%s] %s:%d  %s
", sev, f.File, f.Line, f.Message)
		if f.Value != "" {
			fmt.Fprintf(r.out, "      %s
", f.Value)
		}
	}
	counts := finding.CountBySeverity(fs)
	var parts []string
	for _, s := range []finding.Severity{finding.SeverityCritical,
		finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	fmt.Fprintf(r.out, "
%d finding(s): %s
", len(fs), strings.Join(parts, ", "))
}

func colorSeverity(s finding.Severity, text string) string {
	switch s {
	case finding.SeverityCritical:
		return color.RedString(text)
	case finding.SeverityHigh:
		return color.YellowString(text)
	case finding.SeverityMedium:
		return color.CyanString(text)
	}
	return text
}

func (r *Renderer) renderJSON(fs []finding.Finding) {
	enc := json.NewEncoder(r.out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(fs)
}

func (r *Renderer) renderCSV(fs []finding.Finding) {
	w := csv.NewWriter(r.out)
	_ = w.Write([]string{"kind", "rule", "severity", "file", "line", "message"})
	for _, f := range fs {
		_ = w.Write([]string{f.Kind, f.RuleID, f.Severity.String(),
			f.File, fmt.Sprint(f.Line), f.Message})
	}
	w.Flush()
}

func (r *Renderer) renderSARIF(fs []finding.Finding) {
	type rule struct {
		ID string `json:"id"`
	}
	type result struct {
		RuleID string `json:"ruleId"`
		Level  string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	doc := struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []rule `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []result `json:"results"`
		} `json:"runs"`
	}{Version: "2.1.0"}
	doc.Runs = append(doc.Runs, struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []rule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}{})
	doc.Runs[0].Tool.Driver.Name = "cipherwall"
	seen := map[string]bool{}
	for _, f := range fs {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			doc.Runs[0].Tool.Driver.Rules = append(
				doc.Runs[0].Tool.Driver.Rules, rule{ID: f.RuleID})
		}
		var res result
		res.RuleID = f.RuleID
		res.Level = "error"
		res.Message.Text = f.Message
		var loc struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		}
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		loc.PhysicalLocation.Region.StartLine = f.Line
		res.Locations = append(res.Locations, loc)
		doc.Runs[0].Results = append(doc.Runs[0].Results, res)
	}
	enc := json.NewEncoder(r.out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}

var _ = sort.Strings
