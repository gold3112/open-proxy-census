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

type Pipeline struct {
	cfg   *config.Config
	store *store.Store
}

func New(cfg *config.Config, s *store.Store) *Pipeline {
	return &Pipeline{cfg: cfg, store: s}
}

func (p *Pipeline) Run(ctx context.Context) {
	log.Println("Starting Pipeline...")

	// Channels
	targets := make(chan string, 10000)
	livePorts := make(chan string, 10000) // ip:port
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

	// 2. Port Scanner (Skip for now as most sources are lists with ports)
	// In a real census with CIDRs, we would have port scanners here.
	// For now, we just pass targets directly if they have ports, 
	// or expand them if we implement CIDR + Port logic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(livePorts)
		// Bypass port scanner for list sources, but could be added here
		for target := range targets {
			livePorts <- target
		}
	}()

	// 3. Proxy Tester
	for i := 0; i < p.cfg.Workers.ProxyTester; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runTester(livePorts, tested)
		}()
	}

	// Closer for tested channel
	go func() {
		wg.Wait()
		close(tested)
	}()

	// 4. Analyzer
	var analysisWg sync.WaitGroup
	for i := 0; i < p.cfg.Workers.Analyzer; i++ {
		analysisWg.Add(1)
		go func() {
			defer analysisWg.Done()
			p.runAnalyzer(tested, analyzed)
		}()
	}

	// Closer for analyzed channel
	go func() {
		analysisWg.Wait()
		close(analyzed)
	}()

	// 5. Storage (Sink)
	p.runStorage(analyzed)
}

func (p *Pipeline) runCollector(out chan<- string) {
	// 1. List Sources
	for _, src := range p.cfg.Targets.Sources {
		log.Printf("Collecting from %s", src)
		c := &crawler.URLCrawler{URL: src}
		list, err := c.Fetch()
		if err != nil {
			log.Printf("Failed to fetch %s: %v", src, err)
			continue
		}
		for _, item := range list {
			out <- item
		}
	}
	
	// 2. CIDR / Random (Not implemented fully yet, placeholder)
	// if len(p.cfg.Targets.CIDRs) > 0 { ... }
}

func (p *Pipeline) runTester(in <-chan string, out chan<- *store.Proxy) {
	for addr := range in {
		// Basic check
		res := checker.Check(addr)
		
		status := "dead"
		if res.Alive {
			status = "active"
		}

		// Parse IP:Port
		parts := strings.Split(addr, ":")
		if len(parts) != 2 {
			continue
		}
		port := 0
		fmt.Sscanf(parts[1], "%d", &port)

		proxy := &store.Proxy{
			IP:           parts[0],
			Port:         port,
			Protocol:     "http",
			Country:      res.Country,
			Anonymity:    res.Anonymity,
			ResponseTime: res.ResponseTime.Milliseconds(),
			LastChecked:  time.Now(),
			Status:       status,
		}
		out <- proxy
	}
}

func (p *Pipeline) runAnalyzer(in <-chan *store.Proxy, out chan<- *store.Proxy) {
	for proxy := range in {
		if proxy.Status == "active" {
			// Deep Analysis
			result := analysis.Analyze(proxy.IP, proxy.Port)
			proxy.Software = result.Software
			proxy.Blacklisted = result.Blacklisted
			
			// Abuse Email
			email, err := notifier.GetAbuseEmail(proxy.IP)
			if err == nil {
				proxy.AbuseEmail = email
			}
			
			log.Printf("[ANALYZED] %s:%d (Soft: %s, BL: %v, Email: %s)", proxy.IP, proxy.Port, proxy.Software, proxy.Blacklisted, proxy.AbuseEmail)
		}
		out <- proxy
	}
}

func (p *Pipeline) runStorage(in <-chan *store.Proxy) {
	count := 0
	activeCount := 0
	for proxy := range in {
		count++
		if proxy.Status == "active" {
			activeCount++
		}
		if err := p.store.SaveProxy(proxy); err != nil {
			log.Printf("DB Error: %v", err)
		}
	}
	log.Printf("Pipeline finished. Processed: %d, Active: %d", count, activeCount)
}
