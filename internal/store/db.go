package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Proxy struct {
	ID            int64
	IP            string
	Port          int
	Protocol      string
	Country       string
	Anonymity     string
	AbuseEmail    string
	Software      string
	Blacklisted   bool
	ResponseTime  int64 // ms
	LastChecked   time.Time
	FirstSeen     time.Time
	LastSeenAlive time.Time
	CreatedAt     time.Time
	Status        string
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Performance optimization
	_, _ = db.Exec("PRAGMA journal_mode=WAL;")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL;")

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

func (s *Store) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS proxies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT,
		country TEXT,
		anonymity TEXT,
		abuse_email TEXT,
		software TEXT,
		blacklisted BOOLEAN,
		response_time INTEGER,
		last_checked DATETIME,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen_alive DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT,
		UNIQUE(ip, port)
	);
	`
	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveProxy(p *Proxy) error {
	query := `
	INSERT INTO proxies (ip, port, protocol, country, anonymity, abuse_email, software, blacklisted, response_time, last_checked, last_seen_alive, status)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip, port) DO UPDATE SET
		protocol = excluded.protocol,
		country = CASE WHEN excluded.country != 'unknown' THEN excluded.country ELSE proxies.country END,
		anonymity = excluded.anonymity,
		abuse_email = CASE WHEN excluded.abuse_email != '' THEN excluded.abuse_email ELSE proxies.abuse_email END,
		software = CASE WHEN excluded.software != '' THEN excluded.software ELSE proxies.software END,
		blacklisted = excluded.blacklisted,
		response_time = excluded.response_time,
		last_checked = excluded.last_checked,
		last_seen_alive = CASE WHEN excluded.status = 'active' THEN excluded.last_checked ELSE proxies.last_seen_alive END,
		status = excluded.status
	`
	_, err := s.db.Exec(query, p.IP, p.Port, p.Protocol, p.Country, p.Anonymity, p.AbuseEmail, p.Software, p.Blacklisted, p.ResponseTime, p.LastChecked, p.LastChecked, p.Status)
	if err != nil {
		return fmt.Errorf("failed to save proxy: %w", err)
	}
	return nil
}

func (s *Store) GetStats() (map[string]int, error) {
	stats := map[string]int{"total": 0, "active": 0, "avg_lifespan_hours": 0}
	var total, active int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM proxies").Scan(&total)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM proxies WHERE status = 'active'").Scan(&active)
	stats["total"] = total
	stats["active"] = active
	var avg sql.NullFloat64
	_ = s.db.QueryRow("SELECT AVG(strftime('%s', last_seen_alive) - strftime('%s', first_seen)) / 3600 FROM proxies WHERE last_seen_alive IS NOT NULL").Scan(&avg)
	if avg.Valid { stats["avg_lifespan_hours"] = int(avg.Float64) }
	return stats, nil
}

func (s *Store) GetCountryStats() (map[string]int, error) {
	rows, err := s.db.Query("SELECT country, COUNT(*) FROM proxies WHERE status = 'active' AND country IS NOT NULL GROUP BY country")
	if err != nil { return nil, err }
	defer rows.Close()
	stats := make(map[string]int)
	for rows.Next() {
		var c string
		var count int
		if err := rows.Scan(&c, &count); err == nil && c != "" && c != "unknown" { stats[c] = count }
	}
	return stats, nil
}

func (s *Store) GetAnonymityStats() (map[string]int, error) {
	rows, err := s.db.Query("SELECT anonymity, COUNT(*) FROM proxies WHERE status = 'active' GROUP BY anonymity")
	if err != nil { return nil, err }
	defer rows.Close()
	stats := make(map[string]int)
	for rows.Next() {
		var a string
		var count int
		if err := rows.Scan(&a, &count); err == nil { stats[a] = count }
	}
	return stats, nil
}

func (s *Store) GetResponseTimeStats() (map[string]int, error) {
	query := `SELECT CASE WHEN response_time < 500 THEN '0-500ms' WHEN response_time < 1000 THEN '500-1000ms' WHEN response_time < 2000 THEN '1s-2s' ELSE '2s+' END as r, COUNT(*) FROM proxies WHERE status = 'active' GROUP BY r`
	rows, err := s.db.Query(query)
	if err != nil { return nil, err }
	defer rows.Close()
	stats := make(map[string]int)
	for rows.Next() {
		var r string
		var count int
		if err := rows.Scan(&r, &count); err == nil { stats[r] = count }
	}
	return stats, nil
}

func (s *Store) GetSoftwareStats() (map[string]int, error) {
	rows, err := s.db.Query("SELECT software, COUNT(*) FROM proxies WHERE status = 'active' GROUP BY software ORDER BY COUNT(*) DESC LIMIT 10")
	if err != nil { return nil, err }
	defer rows.Close()
	stats := make(map[string]int)
	for rows.Next() {
		var sw string
		var count int
		if err := rows.Scan(&sw, &count); err == nil && sw != "" { stats[sw] = count }
	}
	return stats, nil
}

func (s *Store) GetBlacklistStats() (map[string]int, error) {
	stats := map[string]int{"clean": 0, "blacklisted": 0}
	rows, err := s.db.Query("SELECT blacklisted, COUNT(*) FROM proxies WHERE status = 'active' GROUP BY blacklisted")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var bl bool
			var count int
			if err := rows.Scan(&bl, &count); err == nil {
				if bl { stats["blacklisted"] = count } else { stats["clean"] = count }
			}
		}
	}
	return stats, nil
}

func (s *Store) GetLifespanStats() (map[string]int, error) {
	query := `SELECT CASE WHEN (strftime('%s', last_seen_alive) - strftime('%s', first_seen)) < 3600 THEN '< 1h' WHEN (strftime('%s', last_seen_alive) - strftime('%s', first_seen)) < 86400 THEN '1h - 1d' WHEN (strftime('%s', last_seen_alive) - strftime('%s', first_seen)) < 604800 THEN '1d - 7d' ELSE '7d+' END as r, COUNT(*) FROM proxies WHERE last_seen_alive IS NOT NULL GROUP BY r`
	rows, err := s.db.Query(query)
	if err != nil { return nil, err }
	defer rows.Close()
	stats := make(map[string]int)
	for rows.Next() {
		var r string
		var count int
		if err := rows.Scan(&r, &count); err == nil { stats[r] = count }
	}
	return stats, nil
}

func (s *Store) GetActiveProxies() ([]Proxy, error) {
	rows, err := s.db.Query("SELECT ip, port, country, response_time, anonymity FROM proxies WHERE status = 'active' ORDER BY last_checked DESC LIMIT 10")
	if err != nil { return nil, err }
	defer rows.Close()
	var proxies []Proxy
	for rows.Next() {
		var p Proxy
		if err := rows.Scan(&p.IP, &p.Port, &p.Country, &p.ResponseTime, &p.Anonymity); err == nil { proxies = append(proxies, p) }
	}
	return proxies, nil
}
