package server

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/mstfugurlu/dhcp-server/internal/store"
)

//go:embed templates/*
var templates embed.FS

type WebServer struct {
	store    *store.Store
	auth     *AuthManager
	addr     string
	tmpl     *template.Template
}

func NewWebServer(st *store.Store, addr string) *WebServer {
	tmpl := template.Must(template.ParseFS(templates, "templates/*.html"))

	return &WebServer{
		store: st,
		auth:  NewAuthManager(),
		addr:  addr,
		tmpl:  tmpl,
	}
}

func (s *WebServer) Start() error {
	mux := http.NewServeMux()

	// public
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/setup", s.handleSetup)

	// protected pages
	mux.HandleFunc("/", s.authMiddleware(s.handleDashboard))
	mux.HandleFunc("/scopes", s.authMiddleware(s.handleScopes))
	mux.HandleFunc("/scopes/new", s.authMiddleware(s.handleScopeNew))
	mux.HandleFunc("/scopes/edit", s.authMiddleware(s.handleScopeEdit))
	mux.HandleFunc("/leases", s.authMiddleware(s.handleLeases))
	mux.HandleFunc("/reservations", s.authMiddleware(s.handleReservations))

	// API
	mux.HandleFunc("/api/scopes", s.apiAuthMiddleware(s.apiScopes))
	mux.HandleFunc("/api/scopes/", s.apiAuthMiddleware(s.apiScope))
	mux.HandleFunc("/api/leases", s.apiAuthMiddleware(s.apiLeases))
	mux.HandleFunc("/api/leases/", s.apiAuthMiddleware(s.apiLease))
	mux.HandleFunc("/api/reservations", s.apiAuthMiddleware(s.apiReservations))
	mux.HandleFunc("/api/reservations/", s.apiAuthMiddleware(s.apiReservation))
	mux.HandleFunc("/api/stats", s.apiAuthMiddleware(s.apiStats))

	log.Printf("Web server listening on %s", s.addr)
	return http.ListenAndServe(s.addr, mux)
}

// Page handlers

func (s *WebServer) handleSetup(w http.ResponseWriter, r *http.Request) {
	count, _ := s.store.UserCount()
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			s.renderPage(w, "setup.html", map[string]any{"Error": "Username and password required"})
			return
		}

		user := &store.User{
			Username:     username,
			PasswordHash: HashPassword(password),
		}
		if err := s.store.CreateUser(user); err != nil {
			s.renderPage(w, "setup.html", map[string]any{"Error": err.Error()})
			return
		}

		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	s.renderPage(w, "setup.html", nil)
}

func (s *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// redirect to setup if no users
	count, _ := s.store.UserCount()
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, _ := s.store.GetUserByUsername(username)
		if user == nil || !CheckPassword(password, user.PasswordHash) {
			s.renderPage(w, "login.html", map[string]any{"Error": "Invalid credentials"})
			return
		}

		token := s.auth.CreateSession(user.ID, user.Username)
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
		})

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	s.renderPage(w, "login.html", nil)
}

func (s *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.auth.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	stats, _ := s.store.GetStats()
	scopes, _ := s.store.GetScopes()
	leases, _ := s.store.GetAllLeases()

	// recent leases
	recentLeases := leases
	if len(recentLeases) > 10 {
		recentLeases = recentLeases[len(recentLeases)-10:]
	}

	s.renderPage(w, "dashboard.html", map[string]any{
		"Stats":        stats,
		"Scopes":       scopes,
		"RecentLeases": recentLeases,
	})
}

func (s *WebServer) handleScopes(w http.ResponseWriter, r *http.Request) {
	scopes, _ := s.store.GetScopes()
	s.renderPage(w, "scopes.html", map[string]any{
		"Scopes": scopes,
	})
}

func (s *WebServer) handleScopeNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		leaseDuration, _ := strconv.Atoi(r.FormValue("lease_duration"))
		if leaseDuration == 0 {
			leaseDuration = 86400
		}

		scope := &store.Scope{
			Name:          r.FormValue("name"),
			Network:       r.FormValue("network"),
			SubnetMask:    r.FormValue("subnet_mask"),
			RangeStart:    r.FormValue("range_start"),
			RangeEnd:      r.FormValue("range_end"),
			Gateway:       r.FormValue("gateway"),
			DNS:           r.FormValue("dns"),
			LeaseDuration: leaseDuration,
			Enabled:       r.FormValue("enabled") == "on",
		}

		if err := s.store.CreateScope(scope); err != nil {
			s.renderPage(w, "scope_form.html", map[string]any{"Error": err.Error(), "Scope": scope})
			return
		}

		http.Redirect(w, r, "/scopes", http.StatusFound)
		return
	}

	s.renderPage(w, "scope_form.html", map[string]any{
		"IsNew": true,
		"Scope": &store.Scope{LeaseDuration: 86400, Enabled: true},
	})
}

func (s *WebServer) handleScopeEdit(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	scope, err := s.store.GetScope(id)
	if err != nil {
		http.Redirect(w, r, "/scopes", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		if r.FormValue("_method") == "DELETE" {
			s.store.DeleteScope(id)
			http.Redirect(w, r, "/scopes", http.StatusFound)
			return
		}

		leaseDuration, _ := strconv.Atoi(r.FormValue("lease_duration"))
		scope.Name = r.FormValue("name")
		scope.Network = r.FormValue("network")
		scope.SubnetMask = r.FormValue("subnet_mask")
		scope.RangeStart = r.FormValue("range_start")
		scope.RangeEnd = r.FormValue("range_end")
		scope.Gateway = r.FormValue("gateway")
		scope.DNS = r.FormValue("dns")
		scope.LeaseDuration = leaseDuration
		scope.Enabled = r.FormValue("enabled") == "on"

		if err := s.store.UpdateScope(scope); err != nil {
			s.renderPage(w, "scope_form.html", map[string]any{"Error": err.Error(), "Scope": scope})
			return
		}

		http.Redirect(w, r, "/scopes", http.StatusFound)
		return
	}

	s.renderPage(w, "scope_form.html", map[string]any{
		"IsNew": false,
		"Scope": scope,
	})
}

func (s *WebServer) handleLeases(w http.ResponseWriter, r *http.Request) {
	scopeIDStr := r.URL.Query().Get("scope")
	scopeID, _ := strconv.ParseInt(scopeIDStr, 10, 64)

	scopes, _ := s.store.GetScopes()

	var leases []store.Lease
	if scopeID > 0 {
		leases, _ = s.store.GetLeases(scopeID)
	} else {
		leases, _ = s.store.GetAllLeases()
	}

	s.renderPage(w, "leases.html", map[string]any{
		"Scopes":      scopes,
		"Leases":      leases,
		"SelectedScope": scopeID,
		"Now":         time.Now(),
	})
}

func (s *WebServer) handleReservations(w http.ResponseWriter, r *http.Request) {
	scopeIDStr := r.URL.Query().Get("scope")
	scopeID, _ := strconv.ParseInt(scopeIDStr, 10, 64)

	scopes, _ := s.store.GetScopes()

	if r.Method == "POST" {
		if r.FormValue("_method") == "DELETE" {
			resID, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
			s.store.DeleteReservation(resID)
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}

		reservation := &store.Reservation{
			ScopeID:     scopeID,
			IP:          r.FormValue("ip"),
			MAC:         r.FormValue("mac"),
			Hostname:    r.FormValue("hostname"),
			Description: r.FormValue("description"),
		}

		if scopeID == 0 {
			// find scope from IP
			ip := net.ParseIP(reservation.IP)
			if ip != nil {
				if sc, _ := s.store.FindScopeForNetwork(ip); sc != nil {
					reservation.ScopeID = sc.ID
				}
			}
		}

		s.store.CreateReservation(reservation)
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return
	}

	var reservations []store.Reservation
	if scopeID > 0 {
		reservations, _ = s.store.GetReservations(scopeID)
	} else {
		for _, sc := range scopes {
			res, _ := s.store.GetReservations(sc.ID)
			reservations = append(reservations, res...)
		}
	}

	s.renderPage(w, "reservations.html", map[string]any{
		"Scopes":        scopes,
		"Reservations":  reservations,
		"SelectedScope": scopeID,
	})
}

// API handlers

func (s *WebServer) apiScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := s.store.GetScopes()
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonResponse(w, scopes)
}

func (s *WebServer) apiScope(w http.ResponseWriter, r *http.Request) {
	// /api/scopes/{id}
	idStr := r.URL.Path[len("/api/scopes/"):]
	id, _ := strconv.ParseInt(idStr, 10, 64)

	switch r.Method {
	case "GET":
		scope, err := s.store.GetScope(id)
		if err != nil {
			jsonError(w, "not found", 404)
			return
		}
		jsonResponse(w, scope)

	case "DELETE":
		s.store.DeleteScope(id)
		jsonResponse(w, map[string]string{"status": "ok"})
	}
}

func (s *WebServer) apiLeases(w http.ResponseWriter, r *http.Request) {
	leases, _ := s.store.GetAllLeases()
	jsonResponse(w, leases)
}

func (s *WebServer) apiLease(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/leases/"):]
	id, _ := strconv.ParseInt(idStr, 10, 64)

	if r.Method == "DELETE" {
		s.store.DeleteLease(id)
		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}
}

func (s *WebServer) apiReservations(w http.ResponseWriter, r *http.Request) {
	scopes, _ := s.store.GetScopes()
	var all []store.Reservation
	for _, sc := range scopes {
		res, _ := s.store.GetReservations(sc.ID)
		all = append(all, res...)
	}
	jsonResponse(w, all)
}

func (s *WebServer) apiReservation(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/reservations/"):]
	id, _ := strconv.ParseInt(idStr, 10, 64)

	if r.Method == "DELETE" {
		s.store.DeleteReservation(id)
		jsonResponse(w, map[string]string{"status": "ok"})
	}
}

func (s *WebServer) apiStats(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	jsonResponse(w, stats)
}

// helpers

func (s *WebServer) renderPage(w http.ResponseWriter, name string, data any) {
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "internal error", 500)
	}
}

func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
