// Package config loads and validates cipherwall.yaml.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level scan configuration.
type Config struct {
	Scan         ScanConfig   `yaml:"scan"`
	Secrets      SecretsConfig `yaml:"secrets"`
	Dependencies DepConfig    `yaml:"dependencies"`
	Output       OutputConfig `yaml:"output"`
}

// ScanConfig controls file traversal.
type ScanConfig struct {
	MaxFileSizeMB    int      `yaml:"max_file_size_mb"`
	FollowSymlinks   bool     `yaml:"follow_symlinks"`
	Exclude          []string `yaml:"exclude"`
}

// SecretsConfig controls credential detection.
type SecretsConfig struct {
	Enabled          bool     `yaml:"enabled"`
	EntropyThreshold float64  `yaml:"entropy_threshold"`
	MinLength        int      `yaml:"min_length"`
	Patterns         []string `yaml:"patterns"`
}

// DepConfig controls dependency scanning.
type DepConfig struct {
	Enabled          bool   `yaml:"enabled"`
	MinSeverity      string `yaml:"min_severity"`
	CheckAdvisories  bool   `yaml:"check_advisories"`
	FailOn           string `yaml:"fail_on"`
}

// OutputConfig controls report rendering.
type OutputConfig struct {
	Format               string `yaml:"format"`
	Color                string `yaml:"color"`
	ExitNonzeroOnFindings bool   `yaml:"exit_nonzero_on_findings"`
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		Scan: ScanConfig{
			MaxFileSizeMB:  10,
			FollowSymlinks: false,
			Exclude: []string{"*.lock", "package-lock.json", "vendor/",
				"node_modules/", ".git/"},
		},
		Secrets: SecretsConfig{
			Enabled:          true,
			EntropyThreshold: 4.2,
			MinLength:        16,
			Patterns: []string{"aws_access_key", "github_token",
				"slack_webhook", "private_key_block"},
		},
		Dependencies: DepConfig{
			Enabled:         true,
			MinSeverity:     "high",
			CheckAdvisories: true,
			FailOn:          "high",
		},
		Output: OutputConfig{
			Format:                "table",
			Color:                 "auto",
			ExitNonzeroOnFindings: true,
		},
	}
}

// Load reads cipherwall.yaml, falling back to defaults for missing keys.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // defaults only
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate sanity-checks the loaded config.
func (c *Config) Validate() error {
	switch c.Output.Format {
	case "table", "json", "sarif", "csv":
	default:
		return fmt.Errorf("output.format %q not supported", c.Output.Format)
	}
	if c.Scan.MaxFileSizeMB <= 0 {
		c.Scan.MaxFileSizeMB = 10
	}
	if c.Secrets.MinLength < 8 {
		return fmt.Errorf("secrets.min_length must be >= 8")
	}
	return nil
}

// WriteDefault writes a starter config file.
func WriteDefault(path string) error {
	cfg := Default()
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

var _ = strings.TrimSpace

// ScanTimeoutS bounds a full scan in seconds (0 = unlimited).
type ScanRuntime struct {
	TimeoutS int `yaml:"timeout_s" json:"timeout_s"`
}
