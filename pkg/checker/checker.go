package checker

import (
	"encoding/json"
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
	if err != nil {
		return Result{Alive: false, Error: err}
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	req, _ := http.NewRequest("GET", "http://ip-api.com/json", nil)
	req.Header.Set("User-Agent", "OpenProxyCensus/1.0 (+https://github.com/your-repo/open-proxy-census; Research Project)")

	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return Result{Alive: false, ResponseTime: duration, Error: err}
	}
	defer resp.Body.Close()

	var geo GeoIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return Result{Alive: true, ResponseTime: duration, Error: err}
	}

	return Result{
		Alive:        geo.Status == "success",
		ResponseTime: duration,
		Anonymity:    "unknown",
		Country:      geo.CountryCode,
		ASN:          geo.AS,
		Org:          geo.Org,
	}
}
