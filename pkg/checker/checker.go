package checker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Result struct {
	Alive        bool
	ResponseTime time.Duration
	Anonymity    string
	Country      string
	Error        error
}

type GeoIPResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Query       string  `json:"query"`
}

// Check validates a proxy by attempting to connect through it
func Check(proxyAddr string) Result {
	start := time.Now()
	
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return Result{Alive: false, Error: err}
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second, // Increased timeout for GeoIP API
	}

	// Use ip-api.com to get GeoIP info via the proxy
	resp, err := client.Get("http://ip-api.com/json")
	duration := time.Since(start)

	if err != nil {
		return Result{
			Alive:        false,
			ResponseTime: duration,
			Error:        err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{
			Alive:        false,
			ResponseTime: duration,
			Error:        fmt.Errorf("status code: %d", resp.StatusCode),
		}
	}

	var geo GeoIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return Result{
			Alive:        true, // It connected, but failed to parse JSON
			ResponseTime: duration,
			Anonymity:    "unknown",
			Country:      "unknown",
			Error:        fmt.Errorf("failed to parse geoip: %v", err),
		}
	}

	if geo.Status != "success" {
		return Result{
			Alive:        true,
			ResponseTime: duration,
			Anonymity:    "unknown",
			Country:      "unknown",
		}
	}

	return Result{
		Alive:        true,
		ResponseTime: duration,
		Anonymity:    "unknown", // Still need logic to compare IPs for anonymity
		Country:      geo.CountryCode, // Use 2-letter code
	}
}
