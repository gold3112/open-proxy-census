package crawler

import (
	"bufio"
	"net/http"
	"strings"
)

// Crawler defines the interface for fetching proxy lists
type Crawler interface {
	Fetch() ([]string, error)
}

// SimpleCrawler returns a static list of proxies for testing
type SimpleCrawler struct{}

func (c *SimpleCrawler) Fetch() ([]string, error) {
	return []string{
		"127.0.0.1:8080",
		"1.1.1.1:80",
	}, nil
}

// URLCrawler fetches a proxy list from a URL (text format, one per line)
type URLCrawler struct {
	URL string
}

func (c *URLCrawler) Fetch() ([]string, error) {
	resp, err := http.Get(c.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var proxies []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}
	return proxies, scanner.Err()
}
