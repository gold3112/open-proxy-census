package pipeline

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"open-proxy-census/internal/config"
	"open-proxy-census/internal/store"
	"open-proxy-census/pkg/analysis"
	"open-proxy-census/pkg/checker"
	"open-proxy-census/pkg/collector"
	"open-proxy-census/pkg/crawler"
	"open-proxy-census/pkg/notifier"
)

type Target struct {
	Addr   string
	Source string
}

type Pipeline struct {
	cfg     *config.Config
	store   *store.Store
	limiter *rate.Limiter
}

func New(cfg *config.Config, s *store.Store) *Pipeline {
	return &Pipeline{
		cfg:     cfg,
		store:   s,
		limiter: rate.NewLimiter(rate.Limit(100), 10),
	}
}

func (p *Pipeline) Run(ctx context.Context) {
	log.Println("Starting Safe Pipeline...")

	targetsChan := make(chan Target, 100000)
	livePorts := make(chan Target, 50000)
	tested := make(chan *store.Proxy, 10000)
	analyzed := make(chan *store.Proxy, 10000)

	// 1. Collector & Shuffler
	go func() {
		defer close(targetsChan)
		allTargets := p.collectAll()
		
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(allTargets), func(i, j int) {
			allTargets[i], allTargets[j] = allTargets[j], allTargets[i]
		})

		for _, t := range allTargets {
			targetsChan <- t
		}
	}()

	// 2. Port Scanner with Stats
	var scannerWg sync.WaitGroup
	scanCounter := make(chan int, 100)
	
	// Stats writer
	go func() {
		count := 0
		for n := range scanCounter {
			count += n
			if count >= 100 {
				p.store.IncrementProbeCount(count)
				count = 0
			}
		}
		if count > 0 { p.store.IncrementProbeCount(count) }
	}()

	for i := 0; i < p.cfg.Workers.PortScanner; i++ {
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			for target := range targetsChan {
				_ = p.limiter.Wait(ctx)
				scanCounter <- 1 // Increment stat
				p.runPortScanner(target, livePorts)
			}
		}()
	}

	go func() {
		scannerWg.Wait()
		close(scanCounter)
		close(livePorts)
	}()

	// 3. Proxy Tester
	var testerWg sync.WaitGroup
	for i := 0; i < p.cfg.Workers.ProxyTester; i++ {
		testerWg.Add(1)
		go func() {
			defer testerWg.Done()
			p.runTester(livePorts, tested)
		}()
	}

	go func() {
		testerWg.Wait()
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

	go func() {
		analysisWg.Wait()
		close(analyzed)
	}()

	// 5. Storage
	p.runStorage(analyzed)
}

func (p *Pipeline) collectAll() []Target {
	var all []Target
	dbProxies, err := p.store.GetProxiesToRecheck(10000)
	if err == nil {
		for _, p := range dbProxies {
			all = append(all, Target{Addr: fmt.Sprintf("%s:%d", p.IP, p.Port), Source: p.Source})
		}
	}
	for _, src := range p.cfg.Targets.Sources {
		c := &crawler.URLCrawler{URL: src}
		list, err := c.Fetch()
		if err == nil {
			for _, item := range list {
				if !isPrivateIP(item) {
					all = append(all, Target{Addr: item, Source: src})
				}
			}
		}
	}
	for _, cidr := range p.cfg.Targets.CIDRs {
		ips, err := collector.ExpandCIDR(cidr)
		if err == nil {
			for _, ip := range ips {
				for _, port := range p.cfg.Targets.Ports {
					addr := fmt.Sprintf("%s:%d", ip, port)
					if !isPrivateIP(addr) {
						all = append(all, Target{Addr: addr, Source: "spot:" + cidr})
					}
				}
			}
		}
	}
	return all
}

func isPrivateIP(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil { host = addr }
	ip := net.ParseIP(host)
	if ip == nil { return true }
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func (p *Pipeline) runPortScanner(target Target, out chan<- Target) {
	conn, err := net.DialTimeout("tcp", target.Addr, 2*time.Second)
	if err == nil {
		conn.Close()
		out <- target
	}
}

func (p *Pipeline) runTester(in <-chan Target, out chan<- *store.Proxy) {
	for target := range in {
		res := checker.Check(target.Addr)
		status, lastErr := "dead", ""
		if res.Alive { status = "active" }
		if res.Error != nil { lastErr = res.Error.Error() }
		parts := strings.Split(target.Addr, ":")
		if len(parts) != 2 { continue }
		port := 0
		fmt.Sscanf(parts[1], "%d", &port)
		out <- &store.Proxy{
			IP: parts[0], Port: port, Protocol: "http", Source: target.Source,
			Country: res.Country, ASN: res.ASN, Organization: res.Org,
			Anonymity: res.Anonymity, ResponseTime: res.ResponseTime.Milliseconds(),
			LastChecked: time.Now(), LastError: lastErr, Status: status,
			NextCheck: time.Now().Add(24 * time.Hour),
		}
	}
}

func (p *Pipeline) runAnalyzer(in <-chan *store.Proxy, out chan<- *store.Proxy) {
	for proxy := range in {
		if proxy.Status == "active" {
			result := analysis.Analyze(proxy.IP, proxy.Port)
			proxy.Software, proxy.Blacklisted = result.Software, result.Blacklisted
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
		_ = p.store.SaveProxy(proxy)
	}
	log.Printf("Pipeline finished. Processed: %d, Active: %d", count, active)
}
