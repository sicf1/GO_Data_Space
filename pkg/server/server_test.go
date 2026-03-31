package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"sprout/pkg/api"
)

func newTestHTTPServer(t *testing.T, timeout time.Duration) *httptest.Server {
	t.Helper()

	cfg := Config{
		DBPath:             filepath.Join(t.TempDir(), "server.db"),
		SaltPath:           filepath.Join(t.TempDir(), "server.salt"),
		MasterPassphrase:   "super-secreto",
		SessionIdleTimeout: timeout,
	}
	db, err := openSecureStore(cfg)
	if err != nil {
		t.Fatalf("no se ha podido crear la store segura: %v", err)
	}

	srv := &server{db: db, sessionIdleTimeout: timeout}
	t.Cleanup(func() { _ = db.Close() })

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, url string, v any) (*http.Response, api.Response) {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal falló: %v", err)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	var ar api.Response
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	return resp, ar
}

func TestServer_RoleWorkflowConsentAndQueries(t *testing.T) {
	ts := newTestHTTPServer(t, 30*time.Minute)
	apiURL := ts.URL + "/api"

	_, bootstrap := postJSON(t, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "admin",
		Password: "adminpw",
	})
	if !bootstrap.Success {
		t.Fatalf("bootstrap falló: %s", bootstrap.Message)
	}

	_, adminLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "admin",
		Password: "adminpw",
	})
	if !adminLogin.Success || adminLogin.Role != api.RoleAdmin || adminLogin.Token == "" {
		t.Fatalf("login admin falló: %#v", adminLogin)
	}

	for _, user := range []struct {
		username string
		password string
		role     api.UserRole
	}{
		{"doctor1", "docpw", api.RoleDoctor},
		{"patient1", "patientpw", api.RolePatient},
		{"research1", "respw", api.RoleResearcher},
	} {
		_, create := postJSON(t, apiURL, api.Request{
			Action:   api.ActionCreateUser,
			Token:    adminLogin.Token,
			Username: user.username,
			Password: user.password,
			Role:     user.role,
		})
		if !create.Success {
			t.Fatalf("alta de %s falló: %s", user.username, create.Message)
		}
	}

	_, doctorLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "doctor1",
		Password: "docpw",
	})
	if !doctorLogin.Success || doctorLogin.Role != api.RoleDoctor {
		t.Fatalf("login doctor falló: %#v", doctorLogin)
	}

	record := api.AnonymizedRecord{
		ID:              "rec-1",
		Classification:  "consulta",
		AgeRange:        "18-35",
		Sex:             "F",
		PatientUsername: "patient1",
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		UploadedBy:      "doctor1",
	}
	_, upload := postJSON(t, apiURL, api.Request{
		Action: api.ActionUploadRecord,
		Token:  doctorLogin.Token,
		Record: &record,
	})
	if !upload.Success {
		t.Fatalf("upload falló: %s", upload.Message)
	}

	_, researcherLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "research1",
		Password: "respw",
	})
	if !researcherLogin.Success || researcherLogin.Role != api.RoleResearcher {
		t.Fatalf("login investigador falló: %#v", researcherLogin)
	}

	_, createQuery := postJSON(t, apiURL, api.Request{
		Action: api.ActionCreateQueryRequest,
		Token:  researcherLogin.Token,
		Query:  &api.StatsQuery{Classification: "consulta"},
	})
	if !createQuery.Success {
		t.Fatalf("crear petición falló: %s", createQuery.Message)
	}

	_, pending := postJSON(t, apiURL, api.Request{
		Action:       api.ActionListQueryRequests,
		Token:        adminLogin.Token,
		StatusFilter: api.QueryPending,
	})
	if !pending.Success || len(pending.QueryRequests) != 1 {
		t.Fatalf("listado pendientes inesperado: %#v", pending)
	}

	_, review := postJSON(t, apiURL, api.Request{
		Action:       api.ActionReviewQueryRequest,
		Token:        adminLogin.Token,
		QueryID:      pending.QueryRequests[0].ID,
		ReviewStatus: api.QueryApproved,
	})
	if !review.Success {
		t.Fatalf("revisión falló: %s", review.Message)
	}

	_, approved := postJSON(t, apiURL, api.Request{
		Action:       api.ActionListQueryRequests,
		Token:        researcherLogin.Token,
		StatusFilter: api.QueryApproved,
	})
	if !approved.Success || len(approved.QueryRequests) != 1 {
		t.Fatalf("listado aprobado inesperado: %#v", approved)
	}
	if len(approved.QueryRequests[0].StatsRows) != 1 || approved.QueryRequests[0].StatsRows[0].Count != 1 {
		t.Fatalf("estadísticas aprobadas inesperadas: %#v", approved.QueryRequests[0].StatsRows)
	}

	_, patientLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "patient1",
		Password: "patientpw",
	})
	if !patientLogin.Success || patientLogin.Role != api.RolePatient {
		t.Fatalf("login paciente falló: %#v", patientLogin)
	}

	denyConsent := false
	_, consent := postJSON(t, apiURL, api.Request{
		Action:         api.ActionSetConsent,
		Token:          patientLogin.Token,
		ConsentGranted: &denyConsent,
	})
	if !consent.Success || consent.ConsentGranted == nil || *consent.ConsentGranted {
		t.Fatalf("cambio de consentimiento falló: %#v", consent)
	}

	_, approvedAfterRevoke := postJSON(t, apiURL, api.Request{
		Action:       api.ActionListQueryRequests,
		Token:        researcherLogin.Token,
		StatusFilter: api.QueryApproved,
	})
	if !approvedAfterRevoke.Success || len(approvedAfterRevoke.QueryRequests) != 1 {
		t.Fatalf("listado tras revocación inesperado: %#v", approvedAfterRevoke)
	}
	if len(approvedAfterRevoke.QueryRequests[0].StatsRows) != 0 {
		t.Fatalf("se esperaban estadísticas vacías tras revocar permiso")
	}
}

func TestServer_SessionExpires(t *testing.T) {
	ts := newTestHTTPServer(t, -time.Second)
	apiURL := ts.URL + "/api"

	_, bootstrap := postJSON(t, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "admin",
		Password: "adminpw",
	})
	if !bootstrap.Success {
		t.Fatalf("bootstrap falló: %s", bootstrap.Message)
	}

	_, login := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "admin",
		Password: "adminpw",
	})
	if !login.Success {
		t.Fatalf("login falló: %s", login.Message)
	}

	_, res := postJSON(t, apiURL, api.Request{
		Action: api.ActionListQueryRequests,
		Token:  login.Token,
	})
	if res.Success {
		t.Fatalf("se esperaba sesión expirada")
	}
}

func TestServer_UnknownFieldRejected(t *testing.T) {
	ts := newTestHTTPServer(t, 30*time.Minute)
	apiURL := ts.URL + "/api"

	raw := []byte(`{"action":"register","username":"u","password":"p","nope":123}`)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}

func TestServer_RejectsTrailingJSON(t *testing.T) {
	ts := newTestHTTPServer(t, 30*time.Minute)
	apiURL := ts.URL + "/api"

	raw := []byte(`{"action":"register","username":"u","password":"p"} {"action":"login"}`)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}
