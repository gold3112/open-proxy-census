package analysis

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AnalysisResult struct {
	Software    string
	Blacklisted bool
}

// Analyze performs detailed analysis on a working proxy
func Analyze(ip string, port int) AnalysisResult {
	return AnalysisResult{
		Software:    detectSoftware(ip, port),
		Blacklisted: checkBlacklist(ip),
	}
}

func detectSoftware(ip string, port int) string {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", ip, port))
	if err != nil {
		return "Unknown"
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Request to a lightweight target to inspect headers
	resp, err := client.Get("http://httpbin.org/headers")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	// Check Server header
	server := resp.Header.Get("Server")
	if server != "" {
		return cleanSoftwareName(server)
	}

	// Check Via header
	via := resp.Header.Get("Via")
	if via != "" {
		return cleanSoftwareName(via)
	}

	return "Unknown"
}

func cleanSoftwareName(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > 20 {
		return raw[:20] // Truncate for display
	}
	return raw
}

func checkBlacklist(ip string) bool {
	// Check against common DNSBLs (e.g., zen.spamhaus.org)
	// Note: Be careful with query limits on public DNSBLs.
	
	lists := []string{"zen.spamhaus.org", "b.barracudacentral.org"}
	
	for _, list := range lists {
		lookup := reverseIP(ip) + "." + list
		ips, err := net.LookupIP(lookup)
		if err == nil && len(ips) > 0 {
			return true
		}
	}
	return false
}

func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}
