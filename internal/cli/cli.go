// Package cli wires the command surface: scan, version, init.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/urlvnashezna/cipherwall/internal/config"
	"github.com/urlvnashezna/cipherwall/internal/deps"
	"github.com/urlvnashezna/cipherwall/internal/output"
	"github.com/urlvnashezna/cipherwall/internal/scanner"
)

var version = "1.2.0"

// Execute runs the root command.
func Execute() error {
	root := &cobra.Command{
		Use:   "cipherwall",
		Short: "Secret and dependency scanner",
		Long: `Cipherwall scans a repository for leaked credentials and
vulnerable dependencies. Run it locally, in CI, or as a pre-commit hook.`,
		Version: version,
	}

	var cfgPath string
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "cipherwall.yaml",
		"config file path")

	var scanCmd = &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory for secrets and vulnerable dependencies",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			return runScan(cfg, target)
		},
	}
	scanCmd.Flags().StringP("format", "f", "", "output format override")
	scanCmd.Flags().Bool("no-secrets", false, "skip secret scanning")
	scanCmd.Flags().Bool("no-deps", false, "skip dependency scanning")
	root.AddCommand(scanCmd)

	root.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Write a default cipherwall.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			return config.WriteDefault(cfgPath)
		},
	})

	return root.Execute()
}

func runScan(cfg *config.Config, target string) error {
	format := cfg.Output.Format
	sc, err := scanner.New(cfg)
	if err != nil {
		return err
	}
	secretFindings, err := sc.ScanSecrets(target)
	if err != nil {
		return fmt.Errorf("secret scan: %w", err)
	}
	depFindings, err := deps.Scan(cfg, target)
	if err != nil {
		return fmt.Errorf("dependency scan: %w", err)
	}
	all := append(secretFindings, depFindings...)
	out, err := output.New(format, cfg.Output.Color)
	if err != nil {
		return err
	}
	out.Render(all, target)

	if cfg.Output.ExitNonzeroOnFindings && len(all) > 0 {
		os.Exit(1)
	}
	return nil
}

	var exitOnFindings bool
	scanCmd.Flags().BoolVar(&exitOnFindings, "fail", true, "exit 1 on findings")
