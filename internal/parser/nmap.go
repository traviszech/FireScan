package parser

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/mr-coder20/FireScan/pkg/types"
)

var (
	hostRegex = regexp.MustCompile(`(?s)<host[^>]*>(.*?)</host>`)
	portRegex = regexp.MustCompile(`(?s)<port protocol="([^"]+)" portid="(\d+)">(.*?)</port>`)
	scriptRegex = regexp.MustCompile(`(?s)<script id="([^"]+)"[^>]*output="([^"]*)"`)
)

// ParseNmapXML converts Nmap XML output into structured host results.
func ParseNmapXML(xml string) []types.HostResult {
	var hosts []types.HostResult

	for _, m := range hostRegex.FindAllStringSubmatch(xml, -1) {
		hostData := m[1]
		host := types.HostResult{}

		if ipMatch := regexp.MustCompile(`<address addr="([^"]+)" addrtype="ipv[46]"`).FindStringSubmatch(hostData); len(ipMatch) > 1 {
			host.IP = ipMatch[1]
		}
		if macMatch := regexp.MustCompile(`<address addr="([^"]+)" addrtype="mac"`).FindStringSubmatch(hostData); len(macMatch) > 1 {
			host.MAC = macMatch[1]
		}
		if hnMatch := regexp.MustCompile(`<hostname name="([^"]+)"`).FindStringSubmatch(hostData); len(hnMatch) > 1 {
			host.Hostname = hnMatch[1]
		}
		if statusMatch := regexp.MustCompile(`<status state="([^"]+)"`).FindStringSubmatch(hostData); len(statusMatch) > 1 {
			host.Status = statusMatch[1]
		}
		if osMatch := regexp.MustCompile(`<osmatch name="([^"]+)"`).FindStringSubmatch(hostData); len(osMatch) > 1 {
			host.OS = osMatch[1]
		}

		for _, pm := range portRegex.FindAllStringSubmatch(hostData, -1) {
			pi := types.PortInfo{Protocol: pm[1]}
			pi.Port, _ = strconv.Atoi(pm[2])
			portBody := pm[3]
			if stateMatch := regexp.MustCompile(`<state state="([^"]+)"`).FindStringSubmatch(portBody); len(stateMatch) > 1 {
				pi.State = stateMatch[1]
			}
			if svcMatch := regexp.MustCompile(`<service name="([^"]+)"`).FindStringSubmatch(portBody); len(svcMatch) > 1 {
				pi.Service = svcMatch[1]
				if prodMatch := regexp.MustCompile(`product="([^"]+)"`).FindStringSubmatch(portBody); len(prodMatch) > 1 {
					pi.Product = prodMatch[1]
				}
				if verMatch := regexp.MustCompile(`version="([^"]+)"`).FindStringSubmatch(portBody); len(verMatch) > 1 {
					pi.Version = verMatch[1]
				}
			}
			host.Ports = append(host.Ports, pi)
		}

		host.Vulnerabilities = parseVulnScripts(hostData)
		for _, p := range host.Ports {
			if p.State == "open" {
				host.OpenCount++
			}
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func parseVulnScripts(hostData string) []types.Vulnerability {
	seen := make(map[string]struct{})
	var vulns []types.Vulnerability

	for _, sm := range scriptRegex.FindAllStringSubmatch(hostData, -1) {
		id := sm[1]
		output := unescapeXML(sm[2])
		if !isVulnScript(id, output) {
			continue
		}
		for _, v := range extractVulnEntries(id, output) {
			key := v.ID + v.Title
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			vulns = append(vulns, v)
		}
	}
	return vulns
}

func isVulnScript(id, output string) bool {
	lower := strings.ToLower(id + " " + output)
	return strings.Contains(lower, "vuln") ||
		strings.Contains(lower, "cve-") ||
		strings.Contains(lower, "exploit")
}

func extractVulnEntries(scriptID, output string) []types.Vulnerability {
	var vulns []types.Vulnerability
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		severity := "info"
		switch {
		case strings.Contains(strings.ToLower(line), "critical"):
			severity = "critical"
		case strings.Contains(strings.ToLower(line), "high"):
			severity = "high"
		case strings.Contains(strings.ToLower(line), "medium"):
			severity = "medium"
		case strings.Contains(strings.ToLower(line), "low"):
			severity = "low"
		}
		id := scriptID
		if cve := regexp.MustCompile(`(?i)CVE-\d{4}-\d+`).FindString(line); cve != "" {
			id = cve
		}
		vulns = append(vulns, types.Vulnerability{
			ID:       id,
			Title:    truncate(line, 200),
			Severity: severity,
		})
		if len(vulns) >= 50 {
			break
		}
	}
	if len(vulns) == 0 && strings.TrimSpace(output) != "" {
		vulns = append(vulns, types.Vulnerability{
			ID:       scriptID,
			Title:    truncate(output, 200),
			Severity: "info",
		})
	}
	return vulns
}

func unescapeXML(s string) string {
	replacer := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&amp;", "&",
		"&quot;", `"`,
		"&#39;", "'",
	)
	return replacer.Replace(s)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
