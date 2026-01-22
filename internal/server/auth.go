package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	UserID    int64
	Username  string
	ExpiresAt time.Time
}

type AuthManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

func NewAuthManager() *AuthManager {
	am := &AuthManager{
		sessions: make(map[string]*Session),
	}
	go am.cleanupLoop()
	return am
}

func (am *AuthManager) CreateSession(userID int64, username string) string {
	token := generateToken()

	am.mu.Lock()
	am.sessions[token] = &Session{
		UserID:    userID,
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	am.mu.Unlock()

	return token
}

func (am *AuthManager) GetSession(token string) *Session {
	am.mu.RLock()
	defer am.mu.RUnlock()

	sess, ok := am.sessions[token]
	if !ok || sess.ExpiresAt.Before(time.Now()) {
		return nil
	}
	return sess
}

func (am *AuthManager) DeleteSession(token string) {
	am.mu.Lock()
	delete(am.sessions, token)
	am.mu.Unlock()
}

func (am *AuthManager) cleanupLoop() {
	for {
		time.Sleep(time.Hour)
		am.mu.Lock()
		now := time.Now()
		for token, sess := range am.sessions {
			if sess.ExpiresAt.Before(now) {
				delete(am.sessions, token)
			}
		}
		am.mu.Unlock()
	}
}

func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func CheckPassword(password, hash string) bool {
	return HashPassword(password) == hash
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *WebServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		sess := s.auth.GetSession(cookie.Value)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next(w, r)
	}
}

func (s *WebServer) apiAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		sess := s.auth.GetSession(cookie.Value)
		if sess == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
