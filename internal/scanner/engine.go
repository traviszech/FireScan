package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/mr-coder20/FireScan/internal/config"
	"github.com/mr-coder20/FireScan/internal/targets"
	"github.com/mr-coder20/FireScan/pkg/types"
)

type (
	PortInfo      = types.PortInfo
	HostResult    = types.HostResult
	ScanResult    = types.ScanResult
	Vulnerability = types.Vulnerability
)

type Engine interface {
	Name() string
	Available(tools ToolStatus) bool
	Scan(cfg *config.Config) (*ScanResult, error)
}

type ToolStatus struct {
	Masscan  bool
	RustScan bool
	Nmap     bool
	Naabu    bool
}

func (t ToolStatus) Installed() []string {
	var names []string
	if t.Masscan {
		names = append(names, "masscan")
	}
	if t.RustScan {
		names = append(names, "rustscan")
	}
	if t.Nmap {
		names = append(names, "nmap")
	}
	if t.Naabu {
		names = append(names, "naabu")
	}
	names = append(names, "naive")
	return names
}

func DetectTools() ToolStatus {
	return ToolStatus{
		Masscan:  commandExists("masscan"),
		RustScan: commandExists("rustscan"),
		Nmap:     commandExists("nmap"),
		Naabu:    commandExists("naabu"),
	}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func NewEngineByName(name string) Engine {
	switch name {
	case "masscan":
		return &MasscanEngine{}
	case "rustscan":
		return &RustScanEngine{}
	case "nmap":
		return &NmapEngine{}
	case "naabu":
		return &NaabuEngine{}
	default:
		return &NaiveEngine{}
	}
}

func NewEngine(cfg *config.Config, tools ToolStatus) Engine {
	name := cfg.Engine
	if name == "" || name == "auto" {
		name = SelectEngine(cfg, tools)
	}
	return NewEngineByName(name)
}

func SelectEngine(cfg *config.Config, tools ToolStatus) string {
	chain := BuildFailoverChain(cfg, tools)
	if len(chain) == 0 {
		return "naive"
	}
	return chain[0]
}

func BuildFailoverChain(cfg *config.Config, tools ToolStatus) []string {
	if cfg.Engine != "" && cfg.Engine != "auto" {
		return dedupeEngines([]string{cfg.Engine, "naive"})
	}

	isFullScan := cfg.AllPorts || cfg.Ports == "1-65535"
	isWideScan := targets.IsWideScan(cfg.Target)
	needsDepth := cfg.ServiceDetect || cfg.OSDetect || cfg.VulnScan

	var chain []string
	if cfg.FastMode {
		if tools.RustScan {
			chain = append(chain, "rustscan")
		}
		if tools.Naabu {
			chain = append(chain, "naabu")
		}
		if tools.Masscan && (isWideScan || isFullScan) {
			chain = append(chain, "masscan")
		}
		if tools.Nmap {
			chain = append(chain, "nmap")
		}
		chain = append(chain, "naive")
		return dedupeEngines(chain)
	}

	switch {
	case isWideScan && tools.Masscan && !needsDepth:
		chain = append(chain, "masscan")
	case isFullScan && tools.RustScan:
		chain = append(chain, "rustscan")
	case needsDepth && tools.Nmap:
		chain = append(chain, "nmap")
	case tools.Naabu && !needsDepth:
		chain = append(chain, "naabu")
	case tools.Nmap:
		chain = append(chain, "nmap")
	case tools.RustScan:
		chain = append(chain, "rustscan")
	case tools.Masscan:
		chain = append(chain, "masscan")
	}
	chain = append(chain, "naive")
	return dedupeEngines(chain)
}

func dedupeEngines(names []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// ScanWithFailover tries engines in order until one succeeds.
func ScanWithFailover(cfg *config.Config, tools ToolStatus) (*ScanResult, error) {
	chain := BuildFailoverChain(cfg, tools)
	if cfg.NoFailover && cfg.Engine != "" && cfg.Engine != "auto" {
		chain = []string{cfg.Engine}
	}

	var lastErr error
	var tried []string

	for _, name := range chain {
		engine := NewEngineByName(name)
		if !engine.Available(tools) && name != "naive" {
			continue
		}
		tried = append(tried, name)

		result, err := engine.Scan(cfg)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", name, err)
			continue
		}

		result.Engine = name
		result.Failover = tried
		types.SyncResults(result)
		return result, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all engines failed (%s): %w", strings.Join(tried, " → "), lastErr)
	}
	return nil, fmt.Errorf("no scanning engine available")
}

func MergeResults(results []*ScanResult) *ScanResult {
	if len(results) == 0 {
		return &ScanResult{}
	}
	if len(results) == 1 {
		types.SyncResults(results[0])
		return results[0]
	}

	merged := &ScanResult{
		StartTime: results[0].StartTime,
		Engine:    results[0].Engine,
	}
	targetsSeen := make(map[string]struct{})
	var targetParts []string
	var totalDuration float64

	for _, r := range results {
		if r.Target != "" {
			if _, ok := targetsSeen[r.Target]; !ok {
				targetsSeen[r.Target] = struct{}{}
				targetParts = append(targetParts, r.Target)
			}
		}
		merged.Hosts = append(merged.Hosts, r.Hosts...)
		merged.TotalOpen += r.TotalOpen
		merged.Errors = append(merged.Errors, r.Errors...)
		totalDuration += r.DurationSec
		if merged.Engine == "" {
			merged.Engine = r.Engine
		}
	}

	merged.Target = strings.Join(targetParts, ", ")
	if len(targetParts) > 3 {
		merged.Target = fmt.Sprintf("%s (+%d more)", strings.Join(targetParts[:3], ", "), len(targetParts)-3)
	}
	merged.EndTime = time.Now().Format(time.RFC3339)
	merged.DurationSec = totalDuration
	merged.Duration = fmt.Sprintf("%.1fs", totalDuration)
	types.SyncResults(merged)
	return merged
}

func ToJSON(result *types.ScanResult) string {
	types.SyncResults(result)
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data)
}
