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
	ASN          string
	Org          string
	Error        error
}

type GeoIPResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	AS          string `json:"as"`
	Org         string `json:"org"`
	Query       string `json:"query"`
}

func Check(proxyAddr string) Result {
	start := time.Now()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil { return Result{Alive: false, Error: err} }

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout: 10 * time.Second,
	}

	req, _ := http.NewRequest("GET", "http://ip-api.com/json?fields=status,countryCode,as,org", nil)
	req.Header.Set("User-Agent", "OpenProxyCensus/1.0")

	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil { return Result{Alive: false, ResponseTime: duration, Error: err} }
	defer resp.Body.Close()

	var geo GeoIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return Result{Alive: true, ResponseTime: duration, Error: fmt.Errorf("decode error: %v", err)}
	}

	if geo.Status != "success" {
		return Result{Alive: true, ResponseTime: duration, Country: "??", ASN: "Unknown", Org: "Unknown"}
	}

	return Result{
		Alive:        true,
		ResponseTime: duration,
		Anonymity:    "unknown",
		Country:      geo.CountryCode,
		ASN:          geo.AS,
		Org:          geo.Org,
	}
}

func CheckStrict(proxyAddr string) Result {
	start := time.Now()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil { return Result{Alive: false, Error: err} }

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://httpbin.org/ip")
	duration := time.Since(start)

	if err != nil { return Result{Alive: false, ResponseTime: duration, Error: err} }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{Alive: false, ResponseTime: duration, Error: fmt.Errorf("status: %d", resp.StatusCode)}
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Result{Alive: false, ResponseTime: duration, Error: fmt.Errorf("invalid response body")}
	}

	if _, ok := body["origin"]; !ok {
		return Result{Alive: false, ResponseTime: duration, Error: fmt.Errorf("not a proxy response")}
	}

	return Result{Alive: true, ResponseTime: duration}
}
