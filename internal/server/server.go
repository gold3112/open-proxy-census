package server

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"open-proxy-census/internal/store"
)

type Server struct {
	store *store.Store
	port  string
}

func NewServer(s *store.Store, port string) *Server {
	return &Server{store: s, port: port}
}

func (s *Server) Start() error {
	http.HandleFunc("/", s.handleIndex)
	http.HandleFunc("/api/stats", s.handleStatsAPI)
	
	log.Printf("Starting Web Server at http://localhost%s", s.port)
	return http.ListenAndServe(s.port, nil)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	countryStats, _ := s.store.GetCountryStats()

	data := struct {
		Stats        map[string]interface{}
		CountryStats map[string]int
	}{
		Stats:        stats,
		CountryStats: countryStats,
	}

	tmplPath := filepath.Join("templates", "index.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Failed to parse template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func (s *Server) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	countryStats, _ := s.store.GetCountryStats()
	anonymityStats, _ := s.store.GetAnonymityStats()
	responseTimeStats, _ := s.store.GetResponseTimeStats()
	softwareStats, _ := s.store.GetSoftwareStats()
	blacklistStats, _ := s.store.GetBlacklistStats()
	lifespanStats, _ := s.store.GetLifespanStats()
	activeProxies, _ := s.store.GetActiveProxies()

	data := map[string]interface{}{
		"stats":          stats,
		"countries":      countryStats,
		"anonymity":      anonymityStats,
		"responseTime":   responseTimeStats,
		"software":       softwareStats,
		"blacklist":      blacklistStats,
		"lifespan":       lifespanStats,
		"activeProxies":  activeProxies,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
