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

	srv, err := newServer(db, timeout)
	if err != nil {
		t.Fatalf("no se ha podido crear el servidor de prueba: %v", err)
	}
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
		t.Fatalf("marshal fallo: %v", err)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST fallo: %v", err)
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
		t.Fatalf("bootstrap fallo: %s", bootstrap.Message)
	}

	_, adminLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "admin",
		Password: "adminpw",
	})
	if !adminLogin.Success || adminLogin.Role != api.RoleAdmin || adminLogin.Token == "" {
		t.Fatalf("login admin fallo: %#v", adminLogin)
	}

	for _, user := range []struct {
		username string
		password string
		role     api.UserRole
	}{
		{"doctor1", "docpw", api.RoleDoctor},
		{"patient1", "patientpw", api.RolePatient},
		{"patient2", "patient2pw", api.RolePatient},
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
			t.Fatalf("alta de %s fallo: %s", user.username, create.Message)
		}
	}

	_, doctorLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "doctor1",
		Password: "docpw",
	})
	if !doctorLogin.Success || doctorLogin.Role != api.RoleDoctor {
		t.Fatalf("login doctor fallo: %#v", doctorLogin)
	}

	_, validatePatient1 := postJSON(t, apiURL, api.Request{
		Action:   api.ActionValidatePatient,
		Token:    doctorLogin.Token,
		Username: "patient1",
	})
	if !validatePatient1.Success || validatePatient1.PatientID != "id1" {
		t.Fatalf("validacion de patient1 inesperada: %#v", validatePatient1)
	}

	_, validatePatient2 := postJSON(t, apiURL, api.Request{
		Action:   api.ActionValidatePatient,
		Token:    doctorLogin.Token,
		Username: "patient2",
	})
	if !validatePatient2.Success || validatePatient2.PatientID != "id2" {
		t.Fatalf("validacion de patient2 inesperada: %#v", validatePatient2)
	}

	_, validateMissingPatient := postJSON(t, apiURL, api.Request{
		Action:   api.ActionValidatePatient,
		Token:    doctorLogin.Token,
		Username: "ghost",
	})
	if validateMissingPatient.Success {
		t.Fatalf("se esperaba error al validar paciente inexistente")
	}

	record := api.AnonymizedRecord{
		ID:             "rec-1",
		Classification: "consulta",
		AgeRange:       "18-35",
		Sex:            "F",
		PatientID:      "id1",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		UploadedBy:     "doctor1",
	}
	_, upload := postJSON(t, apiURL, api.Request{
		Action: api.ActionUploadRecord,
		Token:  doctorLogin.Token,
		Record: &record,
	})
	if !upload.Success {
		t.Fatalf("upload fallo: %s", upload.Message)
	}

	_, researcherLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "research1",
		Password: "respw",
	})
	if !researcherLogin.Success || researcherLogin.Role != api.RoleResearcher {
		t.Fatalf("login investigador fallo: %#v", researcherLogin)
	}

	_, createQuery := postJSON(t, apiURL, api.Request{
		Action: api.ActionCreateQueryRequest,
		Token:  researcherLogin.Token,
		Query:  &api.StatsQuery{Classification: "consulta"},
	})
	if !createQuery.Success {
		t.Fatalf("crear peticion fallo: %s", createQuery.Message)
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
		t.Fatalf("revision fallo: %s", review.Message)
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
		t.Fatalf("estadisticas aprobadas inesperadas: %#v", approved.QueryRequests[0].StatsRows)
	}

	_, patientLogin := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "patient1",
		Password: "patientpw",
	})
	if !patientLogin.Success || patientLogin.Role != api.RolePatient {
		t.Fatalf("login paciente fallo: %#v", patientLogin)
	}

	denyConsent := false
	_, consent := postJSON(t, apiURL, api.Request{
		Action:         api.ActionSetConsent,
		Token:          patientLogin.Token,
		ConsentGranted: &denyConsent,
	})
	if !consent.Success || consent.ConsentGranted == nil || *consent.ConsentGranted {
		t.Fatalf("cambio de consentimiento fallo: %#v", consent)
	}

	_, approvedAfterRevoke := postJSON(t, apiURL, api.Request{
		Action:       api.ActionListQueryRequests,
		Token:        researcherLogin.Token,
		StatusFilter: api.QueryApproved,
	})
	if !approvedAfterRevoke.Success || len(approvedAfterRevoke.QueryRequests) != 1 {
		t.Fatalf("listado tras revocacion inesperado: %#v", approvedAfterRevoke)
	}
	if len(approvedAfterRevoke.QueryRequests[0].StatsRows) != 0 {
		t.Fatalf("se esperaban estadisticas vacias tras revocar permiso")
	}
}

func TestServer_MigratesLegacyPatientIdentifiers(t *testing.T) {
	cfg := Config{
		DBPath:             filepath.Join(t.TempDir(), "server.db"),
		SaltPath:           filepath.Join(t.TempDir(), "server.salt"),
		MasterPassphrase:   "super-secreto",
		SessionIdleTimeout: 30 * time.Minute,
	}
	db, err := openSecureStore(cfg)
	if err != nil {
		t.Fatalf("openSecureStore fallo: %v", err)
	}
	defer db.Close()

	legacyPatient := userRecord{
		Username:       "legacy-patient",
		PasswordSalt:   "salt",
		PasswordHash:   "hash",
		Role:           api.RolePatient,
		DataUseAllowed: true,
		CreatedAt:      "2026-01-02T03:04:05Z",
	}
	legacyDoctor := userRecord{
		Username:       "doctor1",
		PasswordSalt:   "salt",
		PasswordHash:   "hash",
		Role:           api.RoleDoctor,
		DataUseAllowed: true,
		CreatedAt:      "2026-01-02T03:04:06Z",
	}
	if err := putJSON(db, usersNamespace, []byte(legacyPatient.Username), legacyPatient); err != nil {
		t.Fatalf("guardando usuario legacy: %v", err)
	}
	if err := putJSON(db, usersNamespace, []byte(legacyDoctor.Username), legacyDoctor); err != nil {
		t.Fatalf("guardando doctor legacy: %v", err)
	}

	legacyRecord := legacyStoredRecord{
		ID:              "legacy-rec",
		Classification:  "consulta",
		AgeRange:        "18-35",
		Sex:             "F",
		PatientUsername: "legacy-patient",
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		UploadedBy:      "doctor1",
	}
	if err := putJSON(db, recordsNamespace, []byte(legacyRecord.ID), legacyRecord); err != nil {
		t.Fatalf("guardando registro legacy: %v", err)
	}

	srv, err := newServer(db, 30*time.Minute)
	if err != nil {
		t.Fatalf("newServer fallo: %v", err)
	}

	user, err := srv.loadUser("legacy-patient")
	if err != nil {
		t.Fatalf("loadUser fallo: %v", err)
	}
	if user.PatientID != "id1" {
		t.Fatalf("se esperaba id1, obtenido %q", user.PatientID)
	}

	var migrated api.AnonymizedRecord
	if err := getJSON(db, recordsNamespace, []byte(legacyRecord.ID), &migrated); err != nil {
		t.Fatalf("leyendo registro migrado: %v", err)
	}
	if migrated.PatientID != "id1" {
		t.Fatalf("se esperaba registro migrado con id1, obtenido %#v", migrated)
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
		t.Fatalf("bootstrap fallo: %s", bootstrap.Message)
	}

	_, login := postJSON(t, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "admin",
		Password: "adminpw",
	})
	if !login.Success {
		t.Fatalf("login fallo: %s", login.Message)
	}

	_, res := postJSON(t, apiURL, api.Request{
		Action: api.ActionListQueryRequests,
		Token:  login.Token,
	})
	if res.Success {
		t.Fatalf("se esperaba sesion expirada")
	}
}

func TestServer_UnknownFieldRejected(t *testing.T) {
	ts := newTestHTTPServer(t, 30*time.Minute)
	apiURL := ts.URL + "/api"

	raw := []byte(`{"action":"register","username":"u","password":"p","nope":123}`)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST fallo: %v", err)
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
		t.Fatalf("POST fallo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}
