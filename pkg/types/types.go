package types

// Vulnerability represents a detected security issue from NSE or similar scripts.
type Vulnerability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
}

// PortInfo describes a scanned port and optional service metadata.
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Product  string `json:"product,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Extra    string `json:"extra,omitempty"`
	OS       string `json:"os,omitempty"`
	CPE      string `json:"cpe,omitempty"`
}

// HostResult aggregates scan data for a single host.
type HostResult struct {
	IP              string          `json:"ip"`
	Hostname        string          `json:"hostname,omitempty"`
	MAC             string          `json:"mac,omitempty"`
	Status          string          `json:"status"`
	Ports           []PortInfo      `json:"ports"`
	OpenCount       int             `json:"open_count"`
	OS              string          `json:"os,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// ScanResult is the canonical scan output structure (CLI + API + JSON).
type ScanResult struct {
	Target      string       `json:"target"`
	StartTime   string       `json:"start_time"`
	EndTime     string       `json:"end_time"`
	Duration    string       `json:"duration"`
	DurationSec float64      `json:"duration_seconds"`
	Hosts       []HostResult `json:"hosts"`
	Results     []HostResult `json:"results"`
	TotalOpen   int          `json:"total_open_ports"`
	Engine      string       `json:"engine_used"`
	Failover    []string     `json:"failover_chain,omitempty"`
	Errors      []string     `json:"errors,omitempty"`
}

// SyncResults mirrors Hosts into Results for jq/README compatibility.
func SyncResults(r *ScanResult) {
	if r == nil {
		return
	}
	r.Results = r.Hosts
}
