package output

import (
	"strings"
	"testing"

	"github.com/mr-coder20/FireScan/pkg/types"
)

func TestFormatHTMLIncludesFriendlyOpenPortSummary(t *testing.T) {
	result := &types.ScanResult{
		Target:    "example.com",
		Engine:    "naive",
		Duration:  "1.2s",
		TotalOpen: 2,
		Hosts: []types.HostResult{{
			IP:        "192.168.1.10",
			Status:    "up",
			OpenCount: 2,
			Ports:     []types.PortInfo{{Port: 80, Protocol: "tcp", State: "open", Service: "http"}, {Port: 443, Protocol: "tcp", State: "open", Service: "https"}},
		}},
	}

	html := FormatHTML(result)
	if !strings.Contains(html, "Open Ports") {
		t.Fatalf("expected HTML report to include an open ports section, got: %s", html)
	}
	if !strings.Contains(html, "192.168.1.10") {
		t.Fatalf("expected HTML report to include host details, got: %s", html)
	}
}
