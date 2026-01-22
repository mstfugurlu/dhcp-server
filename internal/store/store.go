package store

import (
	"database/sql"
	"net"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

type Scope struct {
	ID            int64
	Name          string
	Network       string
	SubnetMask    string
	RangeStart    string
	RangeEnd      string
	Gateway       string
	DNS           string
	LeaseDuration int
	Enabled       bool
	CreatedAt     time.Time
}

type Lease struct {
	ID        int64
	ScopeID   int64
	IP        string
	MAC       string
	Hostname  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Reservation struct {
	ID          int64
	ScopeID     int64
	IP          string
	MAC         string
	Hostname    string
	Description string
	CreatedAt   time.Time
}

type User struct {
	ID           int64
	Username     string
	PasswordHash string
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Scope operations

func (s *Store) CreateScope(sc *Scope) error {
	res, err := s.db.Exec(`
		INSERT INTO scopes (name, network, subnet_mask, range_start, range_end, gateway, dns, lease_duration, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.Name, sc.Network, sc.SubnetMask, sc.RangeStart, sc.RangeEnd, sc.Gateway, sc.DNS, sc.LeaseDuration, sc.Enabled)
	if err != nil {
		return err
	}
	sc.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) GetScopes() ([]Scope, error) {
	rows, err := s.db.Query(`SELECT id, name, network, subnet_mask, range_start, range_end, gateway, dns, lease_duration, enabled, created_at FROM scopes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []Scope
	for rows.Next() {
		var sc Scope
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Network, &sc.SubnetMask, &sc.RangeStart, &sc.RangeEnd, &sc.Gateway, &sc.DNS, &sc.LeaseDuration, &sc.Enabled, &sc.CreatedAt); err != nil {
			return nil, err
		}
		scopes = append(scopes, sc)
	}
	return scopes, nil
}

func (s *Store) GetScope(id int64) (*Scope, error) {
	var sc Scope
	err := s.db.QueryRow(`SELECT id, name, network, subnet_mask, range_start, range_end, gateway, dns, lease_duration, enabled, created_at FROM scopes WHERE id = ?`, id).
		Scan(&sc.ID, &sc.Name, &sc.Network, &sc.SubnetMask, &sc.RangeStart, &sc.RangeEnd, &sc.Gateway, &sc.DNS, &sc.LeaseDuration, &sc.Enabled, &sc.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

func (s *Store) UpdateScope(sc *Scope) error {
	_, err := s.db.Exec(`
		UPDATE scopes SET name=?, network=?, subnet_mask=?, range_start=?, range_end=?, gateway=?, dns=?, lease_duration=?, enabled=?
		WHERE id=?`,
		sc.Name, sc.Network, sc.SubnetMask, sc.RangeStart, sc.RangeEnd, sc.Gateway, sc.DNS, sc.LeaseDuration, sc.Enabled, sc.ID)
	return err
}

func (s *Store) DeleteScope(id int64) error {
	_, err := s.db.Exec(`DELETE FROM scopes WHERE id = ?`, id)
	return err
}

func (s *Store) FindScopeForNetwork(ip net.IP) (*Scope, error) {
	scopes, err := s.GetScopes()
	if err != nil {
		return nil, err
	}

	for _, sc := range scopes {
		if !sc.Enabled {
			continue
		}
		_, network, err := net.ParseCIDR(sc.Network)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return &sc, nil
		}
	}
	return nil, nil
}

// Lease operations

func (s *Store) CreateLease(l *Lease) error {
	res, err := s.db.Exec(`
		INSERT INTO leases (scope_id, ip, mac, hostname, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET mac=?, hostname=?, expires_at=?`,
		l.ScopeID, l.IP, l.MAC, l.Hostname, l.ExpiresAt, l.MAC, l.Hostname, l.ExpiresAt)
	if err != nil {
		return err
	}
	l.ID, _ = res.LastInsertId()

	// log history
	s.db.Exec(`INSERT INTO lease_history (scope_id, ip, mac, hostname, action) VALUES (?, ?, ?, ?, 'assign')`,
		l.ScopeID, l.IP, l.MAC, l.Hostname)

	return nil
}

func (s *Store) GetLeases(scopeID int64) ([]Lease, error) {
	rows, err := s.db.Query(`SELECT id, scope_id, ip, mac, hostname, expires_at, created_at FROM leases WHERE scope_id = ?`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leases []Lease
	for rows.Next() {
		var l Lease
		if err := rows.Scan(&l.ID, &l.ScopeID, &l.IP, &l.MAC, &l.Hostname, &l.ExpiresAt, &l.CreatedAt); err != nil {
			return nil, err
		}
		leases = append(leases, l)
	}
	return leases, nil
}

func (s *Store) GetAllLeases() ([]Lease, error) {
	rows, err := s.db.Query(`SELECT id, scope_id, ip, mac, hostname, expires_at, created_at FROM leases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leases []Lease
	for rows.Next() {
		var l Lease
		if err := rows.Scan(&l.ID, &l.ScopeID, &l.IP, &l.MAC, &l.Hostname, &l.ExpiresAt, &l.CreatedAt); err != nil {
			return nil, err
		}
		leases = append(leases, l)
	}
	return leases, nil
}

func (s *Store) FindLeaseByMAC(mac string) (*Lease, error) {
	var l Lease
	err := s.db.QueryRow(`SELECT id, scope_id, ip, mac, hostname, expires_at, created_at FROM leases WHERE mac = ?`, strings.ToLower(mac)).
		Scan(&l.ID, &l.ScopeID, &l.IP, &l.MAC, &l.Hostname, &l.ExpiresAt, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) FindLeaseByIP(ip string) (*Lease, error) {
	var l Lease
	err := s.db.QueryRow(`SELECT id, scope_id, ip, mac, hostname, expires_at, created_at FROM leases WHERE ip = ?`, ip).
		Scan(&l.ID, &l.ScopeID, &l.IP, &l.MAC, &l.Hostname, &l.ExpiresAt, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) DeleteLease(id int64) error {
	_, err := s.db.Exec(`DELETE FROM leases WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteExpiredLeases() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM leases WHERE expires_at < ?`, time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Reservation operations

func (s *Store) CreateReservation(r *Reservation) error {
	res, err := s.db.Exec(`
		INSERT INTO reservations (scope_id, ip, mac, hostname, description)
		VALUES (?, ?, ?, ?, ?)`,
		r.ScopeID, r.IP, strings.ToLower(r.MAC), r.Hostname, r.Description)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) GetReservations(scopeID int64) ([]Reservation, error) {
	rows, err := s.db.Query(`SELECT id, scope_id, ip, mac, hostname, description, created_at FROM reservations WHERE scope_id = ?`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reservations []Reservation
	for rows.Next() {
		var r Reservation
		if err := rows.Scan(&r.ID, &r.ScopeID, &r.IP, &r.MAC, &r.Hostname, &r.Description, &r.CreatedAt); err != nil {
			return nil, err
		}
		reservations = append(reservations, r)
	}
	return reservations, nil
}

func (s *Store) FindReservationByMAC(mac string) (*Reservation, error) {
	var r Reservation
	err := s.db.QueryRow(`SELECT id, scope_id, ip, mac, hostname, description, created_at FROM reservations WHERE mac = ?`, strings.ToLower(mac)).
		Scan(&r.ID, &r.ScopeID, &r.IP, &r.MAC, &r.Hostname, &r.Description, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) DeleteReservation(id int64) error {
	_, err := s.db.Exec(`DELETE FROM reservations WHERE id = ?`, id)
	return err
}

// User operations

func (s *Store) CreateUser(u *User) error {
	res, err := s.db.Exec(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, u.Username, u.PasswordHash)
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, username, password_hash FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) UserCount() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// Stats

func (s *Store) GetStats() (map[string]int, error) {
	stats := make(map[string]int)

	s.db.QueryRow(`SELECT COUNT(*) FROM scopes WHERE enabled = 1`).Scan(&stats["scopes"])
	s.db.QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&stats["leases"])
	s.db.QueryRow(`SELECT COUNT(*) FROM reservations`).Scan(&stats["reservations"])
	s.db.QueryRow(`SELECT COUNT(*) FROM leases WHERE expires_at > ?`, time.Now()).Scan(&stats["active_leases"])

	return stats, nil
}

func (s *Store) GetUsedIPs(scopeID int64) (map[string]bool, error) {
	used := make(map[string]bool)

	// from leases
	rows, err := s.db.Query(`SELECT ip FROM leases WHERE scope_id = ?`, scopeID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		used[ip] = true
	}
	rows.Close()

	// from reservations
	rows, err = s.db.Query(`SELECT ip FROM reservations WHERE scope_id = ?`, scopeID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		used[ip] = true
	}
	rows.Close()

	return used, nil
}
