package output

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/mr-coder20/FireScan/internal/config"
	"github.com/mr-coder20/FireScan/internal/scanner"
)

func PrintBanner() {
	fmt.Println(config.Banner)
}

func PrintToolStatus(tools scanner.ToolStatus) {
	var parts []string
	if tools.Masscan {
		parts = append(parts, "✅ masscan")
	} else {
		parts = append(parts, "❌ masscan")
	}
	if tools.RustScan {
		parts = append(parts, "✅ rustscan")
	} else {
		parts = append(parts, "❌ rustscan")
	}
	if tools.Nmap {
		parts = append(parts, "✅ nmap")
	} else {
		parts = append(parts, "❌ nmap")
	}
	if tools.Naabu {
		parts = append(parts, "✅ naabu")
	} else {
		parts = append(parts, "❌ naabu")
	}
	fmt.Printf("  Tools: %s\n\n", strings.Join(parts, " | "))
}

func PrintEngineSelection(engine string, cfg *config.Config) {
	fmt.Printf("  Engine: %s\n", engine)
	fmt.Printf("  Target: %s\n", cfg.Target)
	fmt.Printf("  Ports:  %s\n", cfg.Ports)
	fmt.Printf("  Preset: %s\n\n", strings.ToUpper(cfg.Preset))
}

func PrintInteractiveSummary(cfg *config.Config) {
	fmt.Printf("  Mode:   %s\n", map[bool]string{true: "interactive", false: "cli"}[cfg.Interactive])
	fmt.Printf("  Format: %s\n", cfg.Format)
	fmt.Printf("  Quiet:  %t\n\n", cfg.Quiet)
}

func PrintProgress(current, total int, target string) {
	fmt.Printf("\n  [%d/%d] Scanning: %s\n", current, total, target)
}

func PrintError(target string, err error) {
	fmt.Printf("  ✗ Error: %s — %v\n", target, err)
}

func Render(result *scanner.ScanResult, cfg *config.Config) {
	if cfg.OutputFile != "" {
		ext := strings.ToLower(filepath.Ext(cfg.OutputFile))
		var output string
		switch ext {
		case ".json":
			output = formatJSON(result)
		case ".html", ".htm":
			output = FormatHTML(result)
		case ".csv":
			output = "IP,Port,Protocol,State,Service,Version\n" + formatCSV(result)
		default:
			output = formatTable(result)
		}

		dir := filepath.Dir(cfg.OutputFile)
		if dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Printf("  ✗ Error creating directory: %v\n", err)
				return
			}
		}
		if err := os.WriteFile(cfg.OutputFile, []byte(output), 0644); err != nil {
			fmt.Printf("  ✗ Error writing file: %v\n", err)
		} else {
			fmt.Printf("\n  ✓ Report saved to: %s\n", cfg.OutputFile)
			if cfg.Format == "html" || ext == ".html" || ext == ".htm" {
				openReport(cfg.OutputFile)
			}
		}
		return
	}

	var output string
	switch cfg.Format {
	case "json":
		output = formatJSON(result)
	case "csv":
		output = "IP,Port,Protocol,State,Service,Version\n" + formatCSV(result)
	case "html":
		output = FormatHTML(result)
	case "greppable":
		output = formatGreppable(result)
	default:
		output = formatTable(result)
	}

	fmt.Print(output)
}

func openReport(path string) {
	if path == "" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("  ℹ Report saved; open it manually: %s\n", path)
		return
	}
	fmt.Printf("  ↗ Opening report in your default browser...\n")
}

func formatTable(result *scanner.ScanResult) string {
	var b strings.Builder

	b.WriteString(strings.Repeat("═", 70) + "\n")
	b.WriteString("  FireScan Report\n")
	b.WriteString(strings.Repeat("═", 70) + "\n")
	b.WriteString(fmt.Sprintf("  Target:  %s\n", result.Target))
	b.WriteString(fmt.Sprintf("  Engine:  %s\n", result.Engine))
	b.WriteString(fmt.Sprintf("  Time:    %s\n", result.Duration))
	b.WriteString(fmt.Sprintf("  Hosts:   %d\n", len(result.Hosts)))
	b.WriteString(fmt.Sprintf("  Open:    %d\n", result.TotalOpen))
	b.WriteString(strings.Repeat("═", 70) + "\n\n")

	if len(result.Errors) > 0 {
		for _, err := range result.Errors {
			b.WriteString(fmt.Sprintf("  ⚠ %s\n", err))
		}
		b.WriteString("\n")
	}

	for _, host := range result.Hosts {
		b.WriteString(fmt.Sprintf("  %s", host.IP))
		if host.Hostname != "" {
			b.WriteString(fmt.Sprintf(" (%s)", host.Hostname))
		}
		if host.OS != "" {
			b.WriteString(fmt.Sprintf(" [OS: %s]", host.OS))
		}
		b.WriteString("\n")

		if host.OpenCount == 0 {
			b.WriteString("  └─ No open ports found\n\n")
			continue
		}

		b.WriteString(fmt.Sprintf("  ┌─ Open ports: %d\n", host.OpenCount))
		b.WriteString(fmt.Sprintf("  │  %-6s %-6s %-8s %-15s %s\n", "PORT", "PROTO", "STATE", "SERVICE", "VERSION"))
		b.WriteString("  │  " + strings.Repeat("─", 55) + "\n")

		for _, p := range host.Ports {
			svc := p.Service
			if p.Product != "" {
				svc = p.Product
			}
			ver := p.Version
			if ver == "" {
				ver = p.Banner
			}
			if len(ver) > 25 {
				ver = ver[:25] + "…"
			}
			b.WriteString(fmt.Sprintf("  │  %-6d %-6s %-8s %-15s %s\n", p.Port, p.Protocol, p.State, svc, ver))
		}
		b.WriteString("  └─ " + strings.Repeat("─", 55) + "\n\n")
	}

	return b.String()
}

func formatJSON(result *scanner.ScanResult) string {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":"%s"}`, err.Error())
	}
	return string(data)
}

func formatCSV(result *scanner.ScanResult) string {
	var rows []string
	for _, host := range result.Hosts {
		for _, p := range host.Ports {
			row := fmt.Sprintf("%s,%d,%s,%s,%s,%s", escapeCSV(host.IP), p.Port, p.Protocol, p.State, escapeCSV(p.Service), escapeCSV(p.Version))
			rows = append(rows, row)
		}
	}
	return strings.Join(rows, "\n")
}

func escapeCSV(value string) string {
	value = strings.ReplaceAll(value, "\"", "\"\"")
	if strings.ContainsAny(value, ",\n\r") {
		return "\"" + value + "\""
	}
	return value
}

func escapeHTML(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "\"", "&quot;")
	return value
}

func formatGreppable(result *scanner.ScanResult) string {
	var b strings.Builder
	for _, host := range result.Hosts {
		for _, p := range host.Ports {
			if p.State == "open" {
				fmt.Fprintf(&b, "open %s %s %s:%d\n", p.Protocol, strconv.Itoa(p.Port), host.IP, p.Port)
			}
		}
	}
	return b.String()
}

func FormatHTML(result *scanner.ScanResult) string {
	var portRows strings.Builder
	for _, host := range result.Hosts {
		for _, p := range host.Ports {
			stateClass := "state-closed"
			if p.State == "open" {
				stateClass = "state-open"
			} else if p.State == "filtered" {
				stateClass = "state-filtered"
			}
			portRows.WriteString(fmt.Sprintf(`
			<tr class="%s">
				<td><strong>%s</strong></td>
				<td><span class="pill">%d</span></td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
			</tr>`, stateClass, escapeHTML(host.IP), p.Port, p.Protocol, p.State, escapeHTML(p.Service), escapeHTML(p.Version)))
		}
	}

	hostCount := len(result.Hosts)
	openPortCount := result.TotalOpen
	if openPortCount == 0 {
		for _, host := range result.Hosts {
			for _, p := range host.Ports {
				if p.State == "open" {
					openPortCount++
				}
			}
		}
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>FireScan Report — %s</title>
	<style>
		:root { color-scheme: dark; }
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: linear-gradient(135deg, #020617, #111827);
			color: #e5e7eb;
			padding: 24px;
		}
		.container { max-width: 1280px; margin: 0 auto; }
		.header {
			text-align: center;
			padding: 30px 0 24px;
			border-bottom: 1px solid #334155;
			margin-bottom: 24px;
		}
		.header h1 {
			font-size: 2.4em;
			background: linear-gradient(135deg, #38bdf8, #818cf8, #34d399);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}
		.badge { display: inline-block; margin-top: 8px; padding: 6px 12px; border-radius: 999px; background: rgba(56,189,248,0.16); color: #bae6fd; font-size: 0.9em; }
		.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px; }
		.summary-card { background: rgba(15,23,42,0.92); border: 1px solid #334155; border-radius: 14px; padding: 18px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
		.summary-card .label { color: #94a3b8; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.08em; }
		.summary-card .value { font-size: 1.5em; font-weight: 700; margin-top: 6px; }
		.pill { display: inline-block; padding: 4px 8px; border-radius: 999px; background: #1d4ed8; color: white; font-size: 0.85em; }
		.state-open { background: rgba(16,185,129,0.18); color: #ecfdf5; }
		.state-filtered { background: rgba(249,115,22,0.16); color: #ffedd5; }
		.state-closed { background: rgba(15,23,42,0.95); color: #cbd5e1; }
		table { width: 100%%; border-collapse: collapse; background: rgba(15,23,42,0.95); border-radius: 14px; overflow: hidden; margin-top: 6px; }
		th { background: #1e293b; padding: 12px 10px; text-align: left; font-weight: 600; color: #cbd5e1; }
		td { padding: 10px; border-bottom: 1px solid #1f2937; }
		tr:hover { filter: brightness(1.1); }
		.footer { text-align: center; padding: 30px 10px 8px; color: #64748b; font-size: 0.95em; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔥 FireScan Report</h1>
			<div class="badge">Generated by FireScan v%s · Professional Security Intelligence</div>
		</div>
		<div class="summary-grid">
			<div class="summary-card">
				<div class="label">Target</div>
				<div class="value">%s</div>
			</div>
			<div class="summary-card">
				<div class="label">Engine</div>
				<div class="value">%s</div>
			</div>
			<div class="summary-card">
				<div class="label">Duration</div>
				<div class="value">%s</div>
			</div>
			<div class="summary-card">
				<div class="label">Hosts</div>
				<div class="value">%d</div>
			</div>
			<div class="summary-card">
				<div class="label">Open Ports</div>
				<div class="value" style="color: #4ade80;">%d</div>
			</div>
		</div>
		<table>
			<thead>
				<tr>
					<th>IP</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th>
				</tr>
			</thead>
			<tbody>%s</tbody>
		</table>
		<div class="footer">FireScan v%s — MIT License · Designed for analysts, pentesters, and security teams</div>
	</div>
</body>
</html>`,
		result.Target, config.Version,
		result.Target, result.Engine, result.Duration,
		hostCount, openPortCount,
		portRows.String(), config.Version)
}
