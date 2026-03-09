package pipeline

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"open-proxy-census/internal/config"
	"open-proxy-census/internal/store"
	"open-proxy-census/pkg/analysis"
	"open-proxy-census/pkg/checker"
	"open-proxy-census/pkg/crawler"
	"open-proxy-census/pkg/notifier"
)

type Target struct {
	Addr   string
	Source string
}

type Pipeline struct {
	cfg   *config.Config
	store *store.Store
}

func New(cfg *config.Config, s *store.Store) *Pipeline {
	return &Pipeline{cfg: cfg, store: s}
}

func (p *Pipeline) Run(ctx context.Context) {
	log.Println("Starting Pipeline...")

	targets := make(chan Target, 10000)
	tested := make(chan *store.Proxy, 5000)
	analyzed := make(chan *store.Proxy, 5000)

	var wg sync.WaitGroup

	// 1. Collector
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(targets)
		p.runCollector(targets)
	}()

	// 2. Proxy Tester
	for i := 0; i < p.cfg.Workers.ProxyTester; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runTester(targets, tested)
		}()
	}

	// Closer for tested
	go func() {
		wg.Wait()
		close(tested)
	}()

	// 3. Analyzer
	var analysisWg sync.WaitGroup
	for i := 0; i < p.cfg.Workers.Analyzer; i++ {
		analysisWg.Add(1)
		go func() {
			defer analysisWg.Done()
			p.runAnalyzer(tested, analyzed)
		}()
	}

	// Closer for analyzed
	go func() {
		analysisWg.Wait()
		close(analyzed)
	}()

	// 4. Storage
	p.runStorage(analyzed)
}

func (p *Pipeline) runCollector(out chan<- Target) {
	for _, src := range p.cfg.Targets.Sources {
		log.Printf("Collecting from %s", src)
		c := &crawler.URLCrawler{URL: src}
		list, err := c.Fetch()
		if err != nil {
			log.Printf("Failed to fetch %s: %v", src, err)
			continue
		}
		for _, item := range list {
			out <- Target{Addr: item, Source: src}
		}
	}
}

func (p *Pipeline) runTester(in <-chan Target, out chan<- *store.Proxy) {
	for target := range in {
		res := checker.Check(target.Addr)
		
		status := "dead"
		var lastErr string
		if res.Alive {
			status = "active"
		}
		if res.Error != nil {
			lastErr = res.Error.Error()
		}

		parts := strings.Split(target.Addr, ":")
		if len(parts) != 2 { continue }
		port := 0
		fmt.Sscanf(parts[1], "%d", &port)

		proxy := &store.Proxy{
			IP:           parts[0],
			Port:         port,
			Protocol:     "http", // Placeholder for multi-proto detection
			Source:       target.Source,
			Country:      res.Country,
			ASN:          res.ASN,
			Organization: res.Org,
			Anonymity:    res.Anonymity,
			ResponseTime: res.ResponseTime.Milliseconds(),
			LastChecked:  time.Now(),
			LastError:    lastErr,
			Status:       status,
			NextCheck:    time.Now().Add(24 * time.Hour), // Schedule next check
		}
		out <- proxy
	}
}

func (p *Pipeline) runAnalyzer(in <-chan *store.Proxy, out chan<- *store.Proxy) {
	for proxy := range in {
		if proxy.Status == "active" {
			result := analysis.Analyze(proxy.IP, proxy.Port)
			proxy.Software = result.Software
			proxy.Blacklisted = result.Blacklisted
			
			email, err := notifier.GetAbuseEmail(proxy.IP)
			if err == nil { proxy.AbuseEmail = email }
			
			log.Printf("[ANALYZED] %s:%d (%s) - %s", proxy.IP, proxy.Port, proxy.Organization, proxy.Software)
		}
		out <- proxy
	}
}

func (p *Pipeline) runStorage(in <-chan *store.Proxy) {
	count, active := 0, 0
	for proxy := range in {
		count++
		if proxy.Status == "active" { active++ }
		if err := p.store.SaveProxy(proxy); err != nil {
			log.Printf("DB Error: %v", err)
		}
	}
	log.Printf("Pipeline finished. Processed: %d, Active: %d", count, active)
}
