package main

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
)

type Server struct {
	store *Store
}

// ---------- small helpers ----------

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// getUser reads the Bearer token and finds the user. nil if missing or wrong.
func (s *Server) getUser(r *http.Request) *User {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" {
		return nil
	}
	return s.store.FindUserByToken(token)
}

// requireUser writes a 401 and returns nil if the caller is not logged in.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) *User {
	u := s.getUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "missing or invalid token")
	}
	return u
}

// requireAdmin: 401 if not logged in, 403 if not admin.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) *User {
	u := s.requireUser(w, r)
	if u == nil {
		return nil
	}
	if u.Role != "admin" {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return nil
	}
	return u
}

// ---------- routes ----------

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("POST /users", s.handleAddUser)
	mux.HandleFunc("POST /apps", s.handleAddApp)
	mux.HandleFunc("POST /alerts", s.handleReportAlert)
	mux.HandleFunc("GET /alerts", s.handleListAlerts)
	mux.HandleFunc("GET /alerts/{id}", s.handleGetAlert)
	mux.HandleFunc("POST /alerts/{id}/resolve", s.handleResolve)
	return mux
}

// POST /register  (anyone)
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrgName string `json:"orgName"`
		Name    string `json:"name"`
		Email   string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.OrgName) == "" || strings.TrimSpace(body.Name) == "" {
		writeError(w, http.StatusBadRequest, "orgName and name are required")
		return
	}
	if !strings.Contains(body.Email, "@") {
		writeError(w, http.StatusBadRequest, "email must contain @")
		return
	}

	user := s.store.CreateOrgWithAdmin(body.OrgName, body.Name, body.Email)
	writeJSON(w, http.StatusCreated, user)
}

// POST /users  (admin)
func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}

	var body struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !strings.Contains(body.Email, "@") {
		writeError(w, http.StatusBadRequest, "email must contain @")
		return
	}
	if body.Role != "admin" && body.Role != "viewer" {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}

	user := s.store.CreateUser(admin.OrgID, body.Name, body.Email, body.Role)
	writeJSON(w, http.StatusCreated, user)
}

// POST /apps  (admin)
func (s *Server) handleAddApp(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}

	var body struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if body.Platform != "android" && body.Platform != "ios" {
		writeError(w, http.StatusBadRequest, "platform must be android or ios")
		return
	}

	app := s.store.CreateApp(admin.OrgID, body.Name, body.Platform)
	writeJSON(w, http.StatusCreated, app)
}

// POST /alerts  (SDK, uses X-App-Key)
func (s *Server) handleReportAlert(w http.ResponseWriter, r *http.Request) {
	app := s.store.FindAppByKey(r.Header.Get("X-App-Key"))
	if app == nil {
		writeError(w, http.StatusUnauthorized, "missing or invalid app key")
		return
	}

	// severity is a pointer so I can tell "missing" from 0.
	// float64 so that 5.5 can be caught (a whole number is needed).
	var body struct {
		DeviceID   string   `json:"deviceId"`
		ThreatType string   `json:"threatType"`
		Severity   *float64 `json:"severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.DeviceID) == "" || strings.TrimSpace(body.ThreatType) == "" {
		writeError(w, http.StatusBadRequest, "deviceId and threatType are required")
		return
	}
	if body.Severity == nil {
		writeError(w, http.StatusBadRequest, "severity is required")
		return
	}
	sev := *body.Severity
	if sev != math.Trunc(sev) || sev < 1 || sev > 5 {
		writeError(w, http.StatusBadRequest, "severity must be a whole number from 1 to 5")
		return
	}

	alert, created := s.store.ReportAlert(app, body.DeviceID, body.ThreatType, int(sev))
	if created {
		writeJSON(w, http.StatusCreated, alert)
	} else {
		writeJSON(w, http.StatusOK, alert)
	}
}

// GET /alerts  (admin or viewer)
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	user := s.requireUser(w, r)
	if user == nil {
		return
	}

	status := r.URL.Query().Get("status")
	if status != "" && status != "open" && status != "resolved" {
		writeError(w, http.StatusBadRequest, "status must be open or resolved")
		return
	}

	alerts := s.store.ListAlerts(user.OrgID, status)
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// GET /alerts/{id}  (admin or viewer)
func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	user := s.requireUser(w, r)
	if user == nil {
		return
	}

	alert, ok := s.store.GetAlert(user.OrgID, r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

// POST /alerts/{id}/resolve  (admin)
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}

	alert, found, already := s.store.ResolveAlert(admin.OrgID, r.PathValue("id"), admin.UserID)
	if !found {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	if already {
		writeError(w, http.StatusConflict, "alert is already resolved")
		return
	}
	writeJSON(w, http.StatusOK, alert)
}
