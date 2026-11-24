package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// do sends a request straight to the handler (no real server needed)
func do(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// setup: company Acme with an admin, a viewer, an app and one alert.
type setup struct {
	h       http.Handler
	admin   User
	viewer  User
	appKey  string
	alertID string
}

func newSetup(t *testing.T) setup {
	t.Helper()
	h := (&Server{store: NewStore()}).Routes()
	var s setup
	s.h = h

	rec := do(h, "POST", "/register", `{"orgName":"Acme","name":"Asha","email":"asha@acme.test"}`, nil)
	if rec.Code != 201 {
		t.Fatalf("register: got %d", rec.Code)
	}
	json.Unmarshal(rec.Body.Bytes(), &s.admin)

	rec = do(h, "POST", "/users", `{"name":"Vik","email":"vik@acme.test","role":"viewer"}`, bearer(s.admin.Token))
	if rec.Code != 201 {
		t.Fatalf("add viewer: got %d", rec.Code)
	}
	json.Unmarshal(rec.Body.Bytes(), &s.viewer)

	rec = do(h, "POST", "/apps", `{"name":"Acme Pay","platform":"android"}`, bearer(s.admin.Token))
	var app App
	json.Unmarshal(rec.Body.Bytes(), &app)
	s.appKey = app.AppKey

	rec = do(h, "POST", "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`,
		map[string]string{"X-App-Key": s.appKey})
	if rec.Code != 201 {
		t.Fatalf("report alert: got %d", rec.Code)
	}
	var a Alert
	json.Unmarshal(rec.Body.Bytes(), &a)
	s.alertID = a.ID
	return s
}

// 1. viewer cannot resolve
func TestViewerCannotResolve(t *testing.T) {
	s := newSetup(t)
	rec := do(s.h, "POST", "/alerts/"+s.alertID+"/resolve", "", bearer(s.viewer.Token))
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// 2. user from another company gets 404
func TestOtherCompanyGets404(t *testing.T) {
	s := newSetup(t)

	rec := do(s.h, "POST", "/register", `{"orgName":"Beta","name":"Ravi","email":"ravi@beta.test"}`, nil)
	var betaAdmin User
	json.Unmarshal(rec.Body.Bytes(), &betaAdmin)

	rec = do(s.h, "GET", "/alerts/"+s.alertID, "", bearer(betaAdmin.Token))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET: expected 404, got %d", rec.Code)
	}
	rec = do(s.h, "POST", "/alerts/"+s.alertID+"/resolve", "", bearer(betaAdmin.Token))
	if rec.Code != http.StatusNotFound {
		t.Errorf("resolve: expected 404, got %d", rec.Code)
	}
}

// 3. 50 identical alerts at once -> one alert, count 50
func TestFiftyAlertsAtOnce(t *testing.T) {
	s := newSetup(t)
	body := `{"deviceId":"d2","threatType":"FRIDA_DETECTED","severity":4}`

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := do(s.h, "POST", "/alerts", body, map[string]string{"X-App-Key": s.appKey})
			if rec.Code != 200 && rec.Code != 201 {
				t.Errorf("unexpected status %d", rec.Code)
			}
		}()
	}
	wg.Wait()

	rec := do(s.h, "GET", "/alerts?status=open", "", bearer(s.admin.Token))
	var res struct {
		Alerts []Alert `json:"alerts"`
	}
	json.Unmarshal(rec.Body.Bytes(), &res)

	found := 0
	for _, a := range res.Alerts {
		if a.DeviceID == "d2" {
			found++
			if a.Count != 50 {
				t.Errorf("expected count 50, got %d", a.Count)
			}
		}
	}
	if found != 1 {
		t.Errorf("expected exactly 1 alert for d2, got %d", found)
	}
}
