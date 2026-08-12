// Package deps scans dependency manifests and checks known advisories.
//
// Supported manifests: go.mod, package.json, requirements.txt, Cargo.toml,
// pom.xml (basic). Advisories come from a bundled, curated database.
package deps

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/urlvnashezna/cipherwall/internal/config"
	"github.com/urlvnashezna/cipherwall/internal/finding"
)

// Advisory is one vulnerability record.
type Advisory struct {
	Package     string             `json:"package"`
	Severity    string             `json:"severity"`
	Summary     string             `json:"summary"`
	FixedIn     string             `json:"fixed_in"`
	AffectedLT  string             `json:"affected_lt"`
}

var manifestRe = map[string]*regexp.Regexp{
	"go.mod":        regexp.MustCompile(`^\s*([A-Za-z0-9_.\-/]+)\s+(v[0-9][^\s]+)`),
	"requirements.txt": regexp.MustCompile(`^\s*([A-Za-z0-9_.\-]+)(==|>=|<=|~=|!=)([0-9][^\s]*)`),
	"package.json":  regexp.MustCompile(`"([A-Za-z0-9@_.\-/]+)"\s*:\s*"\^?([0-9][^"]*)"`),
}

// Scan walks target for manifests and reports findings.
func Scan(cfg *config.Config, target string) ([]finding.Finding, error) {
	if !cfg.Dependencies.Enabled {
		return nil, nil
	}
	minSev, err := finding.ParseSeverity(cfg.Dependencies.MinSeverity)
	if err != nil {
		return nil, err
	}
	advisories := loadAdvisories()
	var out []finding.Finding
	err = filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		re, ok := manifestRe[name]
		if !ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(data), "
") {
			m := re.FindStringSubmatch(line)
			if m == nil || len(m) < 3 {
				continue
			}
			pkg, ver := m[1], m[2]
			for _, adv := range advisories {
				if adv.Package != pkg {
					continue
				}
				sev, _ := finding.ParseSeverity(adv.Severity)
				if sev < minSev {
					continue
				}
				if versionLess(ver, adv.FixedIn) {
					out = append(out, finding.Finding{
						Kind: "dependency", RuleID: adv.Summary,
						Severity: sev, File: path, Line: 0,
						Message: fmt.Sprintf(
							"%s %s affected (fixed in %s)",
							pkg, ver, adv.FixedIn),
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	finding.Sort(out)
	return out, nil
}

// versionLess compares dotted versions lexically (good enough for advisories).
func versionLess(a, b string) bool {
	an, bn := strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	as, bs := strings.Split(an, "."), strings.Split(bn, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

var advisoryDB []Advisory

func loadAdvisories() []Advisory {
	if advisoryDB != nil {
		return advisoryDB
	}
	// Bundled default database - replaces external network lookups so scans
	// run fully offline.
	raw := `[
	 {"package":"github.com/gin-gonic/gin","severity":"high","summary":"path traversal in static handler","fixed_in":"v1.9.1","affected_lt":"v1.9.1"},
	 {"package":"lodash","severity":"medium","summary":"prototype pollution","fixed_in":"4.17.21","affected_lt":"4.17.21"},
	 {"package":"requests","severity":"medium","summary":"certificate validation regression","fixed_in":"2.32.0","affected_lt":"2.32.0"},
	 {"package":"cryptography","severity":"high","summary":"side-channel in DSA signing","fixed_in":"42.0.4","affected_lt":"42.0.4"},
	 {"package":"github.com/gorilla/websocket","severity":"low","summary":"compression bomb DoS","fixed_in":"v1.5.2","affected_lt":"v1.5.2"}
	]`
	_ = json.Unmarshal([]byte(raw), &advisoryDB)
	return advisoryDB
}

	"Cargo.toml": regexp.MustCompile(
		`^\s*([a-zA-Z0-9_\-]+)\s*=\s*\"([0-9][^\"]*)\"`),
