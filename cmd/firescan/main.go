package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/mr-coder20/FireScan/internal/config"
	"github.com/mr-coder20/FireScan/internal/output"
	"github.com/mr-coder20/FireScan/internal/scanner"
	"github.com/mr-coder20/FireScan/internal/targets"
	"github.com/spf13/cobra"
)

var cfg *config.Config

func main() {
	rootCmd := newRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "firescan",
		Short: "🔥 FireScan — Ultimate Hybrid Port Scanner",
		Long: `FireScan is an intelligent hybrid port scanner that combines
the SPEED of Masscan/RustScan with the DEPTH of Nmap.

  "Speed of Masscan ❄ Depth of Nmap"

It automatically selects the best scanning engine based on your target
and requirements. Supports all major output formats including HTML reports.`,
		Version: config.Version,
		Example: strings.Join([]string{
			"  firescan scanme.nmap.org -p 22,80,443",
			"  firescan 192.168.1.0/24 --all-ports -f html -o report.html",
			"  firescan example.com --top100 --preset fast",
			"  echo '192.168.1.10' | firescan --pipe --format json",
		}, "\n"),
		RunE: runScan,
	}

	rootCmd.Flags().StringP("target", "t", "", "Target IP, hostname, CIDR, or range")
	rootCmd.Flags().StringP("ports", "p", "1-1000", "Port range (e.g. 22,80,443 or 1-1000)")
	rootCmd.Flags().Bool("all-ports", false, "Scan all 65535 ports")
	rootCmd.Flags().Int("top-ports", 0, "Scan top N ports")
	rootCmd.Flags().Bool("top100", false, "Shortcut for --top-ports 100")
	rootCmd.Flags().Bool("top1000", false, "Shortcut for --top-ports 1000")

	rootCmd.Flags().StringP("engine", "e", "auto", "Scanner engine: auto, masscan, rustscan, nmap, naabu, naive")
	rootCmd.Flags().Int("rate", 10000, "Packets per second")
	rootCmd.Flags().Int("retries", 3, "Max retries")
	rootCmd.Flags().IntP("timeout", "T", 30, "Timeout in seconds")
	rootCmd.Flags().IntP("threads", "n", runtime.NumCPU()*2, "Thread count")
	rootCmd.Flags().BoolP("service-detect", "V", true, "Service/version detection")
	rootCmd.Flags().BoolP("os-detect", "O", false, "OS detection")
	rootCmd.Flags().Bool("vuln", false, "Vulnerability scan (Nmap NSE vuln scripts)")
	rootCmd.Flags().Bool("fast", false, "Fast mode")
	rootCmd.Flags().String("preset", "balanced", "Scan preset: balanced, fast, stealth")
	rootCmd.Flags().BoolP("interactive", "i", false, "Launch numbered interactive setup")

	rootCmd.Flags().StringP("output", "o", "", "Output file")
	rootCmd.Flags().StringP("format", "f", "table", "Output format: table, json, csv, html, greppable")
	rootCmd.Flags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.Flags().Bool("no-banner", false, "Hide banner")
	rootCmd.Flags().Bool("pipe", false, "Read targets from stdin")
	rootCmd.Flags().Bool("dry-run", false, "Show the planned scan and exit")
	rootCmd.Flags().Bool("no-failover", false, "Disable automatic engine fallback")
	rootCmd.Flags().Int("max-hosts", targets.DefaultMaxHosts, "Cap the number of expanded hosts")

	rootCmd.SetVersionTemplate(`{{printf "FireScan version %s\n" .Version}}`)
	return rootCmd
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg = config.FromFlags(cmd, args)
	if cfg.Interactive || (!cfg.PipeMode && strings.TrimSpace(cfg.Target) == "") {
		if err := runInteractiveSetup(cfg); err != nil {
			return err
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	if cfg.DryRun {
		tools := scanner.DetectTools()
		fmt.Printf("[FireScan] dry run: target=%q ports=%q engine=%s preset=%s\n", cfg.Target, cfg.Ports, cfg.Engine, cfg.Preset)
		fmt.Printf("[FireScan] available engines: %s\n", strings.Join(tools.Installed(), ", "))
		return nil
	}

	if !cfg.Quiet && !cfg.NoBanner {
		output.PrintBanner()
	}

	tools := scanner.DetectTools()
	if !cfg.Quiet {
		output.PrintInteractiveSummary(cfg)
	}

	engine := scanner.NewEngine(cfg, tools)

	targets, err := cfg.GetTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no target specified. Use: firescan <target> -p <ports>")
	}

	var allResults []*scanner.ScanResult
	for i, target := range targets {
		if len(targets) > 1 && !cfg.Quiet {
			output.PrintProgress(i+1, len(targets), target)
		}
		targetCfg := cfg.CloneForTarget(target)
		result, err := scanner.ScanWithFailover(targetCfg, tools)
		if err != nil {
			output.PrintError(target, err)
			result = &scanner.ScanResult{
				Target: target,
				Engine: engine.Name(),
				Errors: []string{err.Error()},
			}
		}
		allResults = append(allResults, result)
	}

	finalResult := scanner.MergeResults(allResults)
	output.Render(finalResult, cfg)
	if !cfg.Quiet {
		fmt.Printf("\n  ✅ Scan completed successfully. %d host(s) inspected, %d open port(s) found.\n", len(finalResult.Hosts), finalResult.TotalOpen)
	}
	return nil
}

func runInteractiveSetup(cfg *config.Config) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\nInteractive FireScan setup")
	fmt.Println("1) Scan a single target")
	fmt.Println("2) Scan a CIDR / range")
	fmt.Println("3) Read targets from stdin")
	fmt.Println("4) Exit")

	choice, err := promptNumber(reader, "Choose an option", 1, 4)
	if err != nil {
		return err
	}
	if choice == 4 {
		return fmt.Errorf("interactive setup cancelled")
	}

	switch choice {
	case 1:
		cfg.Target, _ = promptText(reader, "Target", cfg.Target)
	case 2:
		cfg.Target, _ = promptText(reader, "Target (CIDR or range)", cfg.Target)
	case 3:
		cfg.PipeMode = true
	}

	if !cfg.PipeMode {
		cfg.Ports, _ = promptText(reader, "Ports", cfg.Ports)
		cfg.Engine, _ = promptChoice(reader, "Engine", []string{"auto", "naive", "nmap", "naabu", "rustscan", "masscan"}, cfg.Engine)
		cfg.Format, _ = promptChoice(reader, "Output format", []string{"table", "json", "csv", "html", "greppable"}, cfg.Format)
		cfg.Preset, _ = promptChoice(reader, "Preset", []string{"balanced", "fast", "stealth"}, cfg.Preset)
		if cfg.OutputFile == "" {
			cfg.OutputFile, _ = promptText(reader, "Output file (optional)", "")
		}
		cfg.Quiet, _ = promptBool(reader, "Quiet mode", cfg.Quiet)
	}
	return nil
}

func promptText(reader *bufio.Reader, label, defaultValue string) (string, error) {
	fmt.Printf("%s [%s]: ", label, defaultValue)
	input, err := reader.ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return defaultValue, err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue, nil
	}
	return input, nil
}

func promptChoice(reader *bufio.Reader, label string, options []string, defaultValue string) (string, error) {
	for i, option := range options {
		fmt.Printf("  %d) %s\n", i+1, option)
	}
	fmt.Printf("%s [%s]: ", label, defaultValue)
	input, err := reader.ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return defaultValue, err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue, nil
	}
	if idx, err := strconv.Atoi(input); err == nil {
		if idx >= 1 && idx <= len(options) {
			return options[idx-1], nil
		}
	}
	for _, option := range options {
		if strings.EqualFold(option, input) {
			return option, nil
		}
	}
	return defaultValue, nil
}

func promptNumber(reader *bufio.Reader, label string, min, max int) (int, error) {
	fmt.Printf("%s: ", label)
	input, err := reader.ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return 0, err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return min, nil
	}
	choice, err := strconv.Atoi(input)
	if err != nil || choice < min || choice > max {
		return 0, fmt.Errorf("invalid selection %q", input)
	}
	return choice, nil
}

func promptBool(reader *bufio.Reader, label string, defaultValue bool) (bool, error) {
	fmt.Printf("%s [y/N]: ", label)
	input, err := reader.ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return defaultValue, err
	}
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultValue, nil
	}
	if input == "y" || input == "yes" || input == "1" {
		return true, nil
	}
	return false, nil
}
