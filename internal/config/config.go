package config

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/mr-coder20/FireScan/internal/targets"
	"github.com/spf13/cobra"
)

const (
	Name     = "FireScan"
	Version  = "5.1.0"
	Homepage = "https://github.com/mr-coder20/FireScan"
)

var Banner = fmt.Sprintf(`
    ███████╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    █████╗  ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
    ██╔══╝  ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║     ██║██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                    
   ╔══════════════════════════════════════════════════════════════╗
   ║     Ultimate Hybrid Port Scanner  v%s                       ║
   ║     "Speed of Masscan ❄ Depth of Nmap"                     ║
   ║     %s                                                      ║
   ╚══════════════════════════════════════════════════════════════╝`, Version, Homepage)

type Config struct {
	Target        string
	Ports         string
	Engine        string
	Rate          int
	Retries       int
	Timeout       int
	Threads       int
	AllPorts      bool
	TopPorts      int
	ServiceDetect bool
	OSDetect      bool
	VulnScan      bool
	FastMode      bool
	OutputFile    string
	Format        string
	Quiet         bool
	NoBanner      bool
	PipeMode      bool
	Interactive   bool
	Preset        string
	CommandLine   string
	DryRun        bool
	NoFailover    bool
	MaxHosts      int
}

func Default() *Config {
	return &Config{
		Ports:         "1-1000",
		Engine:        "auto",
		Rate:          10000,
		Retries:       3,
		Timeout:       30,
		ServiceDetect: true,
		Format:        "table",
		Threads:       runtime.NumCPU() * 2,
		Preset:        "balanced",
		MaxHosts:      targets.DefaultMaxHosts,
	}
}

func FromFlags(cmd *cobra.Command, args []string) *Config {
	cfg := Default()

	cfg.Target, _ = cmd.Flags().GetString("target")
	cfg.Ports, _ = cmd.Flags().GetString("ports")
	cfg.AllPorts, _ = cmd.Flags().GetBool("all-ports")
	cfg.TopPorts, _ = cmd.Flags().GetInt("top-ports")
	cfg.Engine, _ = cmd.Flags().GetString("engine")
	cfg.Rate, _ = cmd.Flags().GetInt("rate")
	cfg.Retries, _ = cmd.Flags().GetInt("retries")
	cfg.Timeout, _ = cmd.Flags().GetInt("timeout")
	if t, _ := cmd.Flags().GetInt("threads"); t > 0 {
		cfg.Threads = t
	}
	cfg.ServiceDetect, _ = cmd.Flags().GetBool("service-detect")
	cfg.OSDetect, _ = cmd.Flags().GetBool("os-detect")
	cfg.VulnScan, _ = cmd.Flags().GetBool("vuln")
	cfg.FastMode, _ = cmd.Flags().GetBool("fast")
	cfg.OutputFile, _ = cmd.Flags().GetString("output")
	cfg.Format, _ = cmd.Flags().GetString("format")
	cfg.Quiet, _ = cmd.Flags().GetBool("quiet")
	cfg.NoBanner, _ = cmd.Flags().GetBool("no-banner")
	cfg.Interactive, _ = cmd.Flags().GetBool("interactive")
	cfg.Preset, _ = cmd.Flags().GetString("preset")
	cfg.DryRun, _ = cmd.Flags().GetBool("dry-run")
	cfg.NoFailover, _ = cmd.Flags().GetBool("no-failover")
	cfg.MaxHosts, _ = cmd.Flags().GetInt("max-hosts")

	if top100, _ := cmd.Flags().GetBool("top100"); top100 {
		cfg.TopPorts = 100
	}
	if top1000, _ := cmd.Flags().GetBool("top1000"); top1000 {
		cfg.TopPorts = 1000
	}

	if strings.TrimSpace(cfg.Preset) == "" {
		cfg.Preset = "balanced"
	}
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = targets.DefaultMaxHosts
	}

	if p, _ := cmd.Flags().GetBool("pipe"); p {
		cfg.PipeMode = true
	}

	if cfg.Target == "" && len(args) > 0 {
		cfg.Target = args[0]
	}

	if !cfg.PipeMode {
		stat, _ := os.Stdin.Stat()
		cfg.PipeMode = (stat.Mode() & os.ModeCharDevice) == 0
	}

	cfg.ApplyOptions()
	cfg.CommandLine = strings.Join(os.Args[1:], " ")
	return cfg
}

// ApplyOptions resolves ports, presets, and fast-mode shortcuts.
func (c *Config) ApplyOptions() {
	ports, err := resolvePortSpec(c.Ports, c.TopPorts, c.AllPorts, c.FastMode)
	if err == nil {
		c.Ports = ports
	}
	c.ApplyPreset()
}

func resolvePortSpec(ports string, topPorts int, allPorts, fastMode bool) (string, error) {
	if allPorts {
		return "1-65535", nil
	}
	if topPorts > 0 {
		if topPorts > 65535 {
			return "", fmt.Errorf("top-ports must be between 1 and 65535")
		}
		return buildTopPortsSpec(topPorts), nil
	}
	if fastMode && (ports == "" || ports == "1-1000") {
		return buildTopPortsSpec(100), nil
	}
	if strings.TrimSpace(ports) == "" {
		return "1-1000", nil
	}
	return ports, nil
}

func buildTopPortsSpec(n int) string {
	if n <= 0 {
		n = 100
	}
	if n > len(commonTopPorts) {
		n = len(commonTopPorts)
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = strconv.Itoa(commonTopPorts[i])
	}
	return strings.Join(parts, ",")
}

var commonTopPorts = []int{80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389, 5900, 8080, 8443, 8000, 6379, 5432, 27017, 23, 111, 995, 993, 587, 465, 1723, 135, 139, 445, 139}

// ApplyPreset tunes rate, timeout, and threads for the selected scan profile.
func (c *Config) ApplyPreset() {
	switch strings.ToLower(c.Preset) {
	case "fast":
		if c.Rate < 20000 {
			c.Rate = 20000
		}
		if c.Timeout > 15 {
			c.Timeout = 15
		}
		if c.Threads < runtime.NumCPU()*4 {
			c.Threads = runtime.NumCPU() * 4
		}
	case "stealth":
		if c.Rate > 500 {
			c.Rate = 500
		}
		if c.Timeout < 60 {
			c.Timeout = 60
		}
		if c.Retries < 2 {
			c.Retries = 2
		}
	}

	if c.FastMode {
		if c.Timeout > 10 {
			c.Timeout = 10
		}
		if c.Rate < 15000 {
			c.Rate = 15000
		}
		c.ServiceDetect = false
		c.OSDetect = false
		c.VulnScan = false
	}
}

func (c *Config) Validate() error {
	if !c.PipeMode && strings.TrimSpace(c.Target) == "" {
		return fmt.Errorf("target is required — try: firescan scan example.com")
	}
	if strings.ContainsAny(c.Target, " \t\r\n") && !c.PipeMode {
		return fmt.Errorf("target contains whitespace — use one target or pipe multiple lines")
	}
	if strings.TrimSpace(c.Ports) == "" {
		return fmt.Errorf("ports cannot be empty")
	}
	if c.Rate <= 0 {
		return fmt.Errorf("rate must be greater than zero")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if c.Threads <= 0 {
		return fmt.Errorf("threads must be greater than zero")
	}
	if c.Retries < 0 {
		return fmt.Errorf("retries cannot be negative")
	}
	if c.TopPorts < 0 || c.TopPorts > 65535 {
		return fmt.Errorf("top-ports must be between 1 and 65535")
	}
	if err := validatePortSpec(c.Ports); err != nil {
		return err
	}
	switch strings.ToLower(c.Engine) {
	case "", "auto", "masscan", "rustscan", "nmap", "naabu", "naive":
	default:
		return fmt.Errorf("unknown engine %q — use: auto, masscan, rustscan, nmap, naabu, naive", c.Engine)
	}
	switch strings.ToLower(c.Format) {
	case "table", "json", "csv", "html", "greppable":
	default:
		return fmt.Errorf("unknown format %q — use: table, json, csv, html, greppable", c.Format)
	}
	switch strings.ToLower(c.Preset) {
	case "balanced", "fast", "stealth":
	default:
		return fmt.Errorf("unsupported preset %q — use: balanced, fast, stealth", c.Preset)
	}
	return nil
}

func validatePortSpec(portSpec string) error {
	if len(portSpec) > 500000 {
		return fmt.Errorf("port specification too large")
	}
	for _, part := range strings.Split(portSpec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			parts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || start < 1 || start > 65535 {
				return fmt.Errorf("invalid port range %q", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || end < 1 || end > 65535 || end < start {
				return fmt.Errorf("invalid port range %q", part)
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %q", part)
		}
	}
	return nil
}

func (c *Config) GetTargets() ([]string, error) {
	var specs []string

	if c.PipeMode {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				specs = append(specs, line)
			}
		}
	} else if c.Target != "" {
		specs = []string{c.Target}
	}

	if len(specs) == 0 {
		return nil, nil
	}
	return targets.ExpandAll(specs, c.MaxHosts)
}

func (c *Config) CloneForTarget(target string) *Config {
	copy := *c
	copy.Target = target
	return &copy
}
