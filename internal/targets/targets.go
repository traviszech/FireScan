package targets

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const DefaultMaxHosts = 4096

// Expand resolves hostnames, CIDR blocks, and IP ranges into individual scan targets.
func Expand(spec string, maxHosts int) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty target")
	}
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}

	if strings.Contains(spec, "/") {
		return expandCIDR(spec, maxHosts)
	}
	if isIPRange(spec) {
		return expandIPRange(spec, maxHosts)
	}
	return []string{spec}, nil
}

// ExpandAll expands multiple target specs (pipe lines, comma-separated batches).
func ExpandAll(specs []string, maxHosts int) ([]string, error) {
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}
	seen := make(map[string]struct{})
	var out []string

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" || strings.HasPrefix(spec, "#") {
			continue
		}
		expanded, err := Expand(spec, maxHosts-len(out))
		if err != nil {
			return nil, err
		}
		for _, t := range expanded {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
			if len(out) >= maxHosts {
				return out, fmt.Errorf("target list capped at %d hosts (use --max-hosts to raise)", maxHosts)
			}
		}
	}
	return out, nil
}

func expandCIDR(spec string, maxHosts int) ([]string, error) {
	ip, network, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", spec, err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR is supported: %q", spec)
	}

	maskOnes, _ := network.Mask.Size()
	hostCount := (1 << uint(32-maskOnes)) - 2
	if maskOnes <= 30 && hostCount > maxHosts {
		return nil, fmt.Errorf("CIDR %s expands to ~%d hosts (max %d); narrow the range or raise --max-hosts", spec, hostCount, maxHosts)
	}

	var targets []string
	for ip := ip.Mask(network.Mask); network.Contains(ip); incIP(ip) {
		if ip.Equal(network.IP) || broadcastIP(ip, network) {
			continue
		}
		targets = append(targets, ip.String())
		if len(targets) >= maxHosts {
			break
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("CIDR %s produced no scannable hosts", spec)
	}
	return targets, nil
}

func expandIPRange(spec string, maxHosts int) ([]string, error) {
	parts := strings.SplitN(spec, "-", 2)
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP range %q", spec)
	}
	start = start.To4()
	end = end.To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported: %q", spec)
	}

	if compareIP(start, end) > 0 {
		start, end = end, start
	}

	count := ipDistance(start, end) + 1
	if count > maxHosts {
		return nil, fmt.Errorf("range %s expands to %d hosts (max %d)", spec, count, maxHosts)
	}

	var targets []string
	for ip := cloneIP(start); compareIP(ip, end) <= 0; incIP(ip) {
		targets = append(targets, ip.String())
	}
	return targets, nil
}

func isIPRange(spec string) bool {
	if !strings.Contains(spec, "-") {
		return false
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return false
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	return net.ParseIP(left) != nil && net.ParseIP(right) != nil
}

func broadcastIP(ip net.IP, network *net.IPNet) bool {
	broadcast := make(net.IP, len(network.IP))
	for i := range network.IP {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func compareIP(a, b net.IP) int {
	aa := a.To4()
	bb := b.To4()
	for i := 0; i < len(aa); i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

func ipDistance(start, end net.IP) int {
	s := ipToUint32(start)
	e := ipToUint32(end)
	if e < s {
		return int(s - e)
	}
	return int(e - s)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// IsWideScan reports whether the target spec likely covers many hosts.
func IsWideScan(spec string) bool {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "/") {
		return true
	}
	if isIPRange(spec) {
		parts := strings.SplitN(spec, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start != nil && end != nil {
			return ipDistance(start.To4(), end.To4()) > 1
		}
	}
	return false
}

// Describe returns a human-readable summary of a target spec.
func Describe(spec string) string {
	if strings.Contains(spec, "/") {
		_, network, err := net.ParseCIDR(spec)
		if err == nil {
			ones, bits := network.Mask.Size()
			if ones < bits {
				hosts := (1 << uint(bits-ones)) - 2
				return fmt.Sprintf("%s (~%d hosts)", spec, hosts)
			}
		}
		return spec
	}
	if isIPRange(spec) {
		parts := strings.SplitN(spec, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start != nil && end != nil {
			return fmt.Sprintf("%s (%d hosts)", spec, ipDistance(start.To4(), end.To4())+1)
		}
	}
	return spec
}

// ParsePortSpec converts a port list into a comma-separated spec (helper for logging).
func ParsePortSpec(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	var b strings.Builder
	for i, p := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(p))
	}
	return b.String()
}
