package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Store keeps everything in memory.
// One mutex protects all of it (simple, and safe for R8).
type Store struct {
	mu sync.Mutex

	orgCount   int
	userCount  int
	appCount   int
	alertCount int
	seq        int

	orgs   map[string]*Org   // by org id
	users  map[string]*User  // by token
	apps   map[string]*App   // by appKey
	appsID map[string]*App   // by app id
	alerts map[string]*Alert // by alert id
}

func NewStore() *Store {
	return &Store{
		orgs:   map[string]*Org{},
		users:  map[string]*User{},
		apps:   map[string]*App{},
		appsID: map[string]*App{},
		alerts: map[string]*Alert{},
	}
}

// randomHex gives 16 random bytes as hex (32 chars). Uses crypto/rand (R7).
func randomHex() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("could not read random bytes")
	}
	return hex.EncodeToString(b)
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ---------- companies and users ----------

// CreateOrgWithAdmin makes a company and its first admin user.
func (s *Store) CreateOrgWithAdmin(orgName, name, email string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.orgCount++
	org := &Org{ID: fmt.Sprintf("org_%d", s.orgCount), Name: orgName}
	s.orgs[org.ID] = org

	return s.addUserLocked(org.ID, name, email, "admin")
}

func (s *Store) CreateUser(orgID, name, email, role string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addUserLocked(orgID, name, email, role)
}

// the "Locked" name means the caller must already hold s.mu
func (s *Store) addUserLocked(orgID, name, email, role string) *User {
	s.userCount++
	u := &User{
		UserID: fmt.Sprintf("usr_%d", s.userCount),
		OrgID:  orgID,
		Name:   name,
		Email:  email,
		Role:   role,
		Token:  randomHex(),
	}
	s.users[u.Token] = u
	return u
}

func (s *Store) FindUserByToken(token string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[token]
}

// ---------- apps ----------

func (s *Store) CreateApp(orgID, name, platform string) *App {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.appCount++
	a := &App{
		AppID:    fmt.Sprintf("app_%d", s.appCount),
		Name:     name,
		Platform: platform,
		AppKey:   randomHex(),
		OrgID:    orgID,
	}
	s.apps[a.AppKey] = a
	s.appsID[a.AppID] = a
	return a
}

func (s *Store) FindAppByKey(key string) *App {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apps[key]
}

// ---------- alerts ----------

// ReportAlert handles a new alert from the SDK.
// Returns the alert and true if it was newly created, false if it was a repeat.
// The whole check-then-create is done while holding the lock, so two
// identical alerts can never both think "there is no open alert" (R8).
func (s *Store) ReportAlert(app *App, deviceID, threatType string, severity int) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	now := nowUTC()

	// look for an open alert with same app + device + threat
	for _, a := range s.alerts {
		if a.AppID == app.AppID && a.DeviceID == deviceID &&
			a.ThreatType == threatType && a.Status == "open" {
			a.Count++
			a.LastSeen = now
			a.Seq = s.seq
			return *a, false
		}
	}

	s.alertCount++
	a := &Alert{
		ID:         fmt.Sprintf("alr_%d", s.alertCount),
		AppID:      app.AppID,
		DeviceID:   deviceID,
		ThreatType: threatType,
		Severity:   severity,
		Count:      1,
		Status:     "open",
		FirstSeen:  now,
		LastSeen:   now,
		ResolvedBy: "",
		OrgID:      app.OrgID,
		Seq:        s.seq,
	}
	s.alerts[a.ID] = a
	return *a, true
}

// ListAlerts returns alerts of one company, newest lastSeen first.
// status can be "" (all), "open" or "resolved".
func (s *Store) ListAlerts(orgID, status string) []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := []Alert{} // not nil, so JSON gives [] and not null
	for _, a := range s.alerts {
		if a.OrgID != orgID {
			continue
		}
		if status != "" && a.Status != status {
			continue
		}
		result = append(result, *a)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Seq > result[j].Seq
	})
	return result
}

// GetAlert returns an alert only if it belongs to the given company.
func (s *Store) GetAlert(orgID, id string) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[id]
	if !ok || a.OrgID != orgID {
		return Alert{}, false
	}
	return *a, true
}

// ResolveAlert marks an alert resolved.
// found=false -> 404, alreadyResolved=true -> 409
func (s *Store) ResolveAlert(orgID, id, userID string) (alert Alert, found bool, alreadyResolved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[id]
	if !ok || a.OrgID != orgID {
		return Alert{}, false, false
	}
	if a.Status == "resolved" {
		return *a, true, true
	}
	a.Status = "resolved"
	a.ResolvedBy = userID
	return *a, true, false
}
