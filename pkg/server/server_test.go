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

func TestServer_AgreementWorkflowConsentAndQueries(t *testing.T) {
	ts := newTestHTTPServer(t, 30*time.Minute)
	apiURL := ts.URL + "/api"

	_, bootstrap := postJSON(t, apiURL, api.Request{
		Action:         api.ActionRegister,
		Username:       "admin-h1",
		Password:       "adminh1pw",
		OrganizationID: api.OrgHospital1,
	})
	if !bootstrap.Success {
		t.Fatalf("bootstrap hospital fallo: %s", bootstrap.Message)
	}

	_, researchBootstrap := postJSON(t, apiURL, api.Request{
		Action:         api.ActionRegister,
		Username:       "admin-r1",
		Password:       "adminr1pw",
		OrganizationID: api.OrgResearchCenter1,
	})
	if !researchBootstrap.Success {
		t.Fatalf("bootstrap centro fallo: %s", researchBootstrap.Message)
	}

	_, hospitalAdminLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "admin-h1",
		Password:       "adminh1pw",
		OrganizationID: api.OrgHospital1,
	})
	if !hospitalAdminLogin.Success || hospitalAdminLogin.Role != api.RoleAdmin || hospitalAdminLogin.Token == "" || hospitalAdminLogin.OrganizationID != api.OrgHospital1 {
		t.Fatalf("login admin hospital fallo: %#v", hospitalAdminLogin)
	}

	_, researchAdminLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "admin-r1",
		Password:       "adminr1pw",
		OrganizationID: api.OrgResearchCenter1,
	})
	if !researchAdminLogin.Success || researchAdminLogin.Role != api.RoleAdmin || researchAdminLogin.Token == "" || researchAdminLogin.OrganizationID != api.OrgResearchCenter1 {
		t.Fatalf("login admin centro fallo: %#v", researchAdminLogin)
	}

	for _, user := range []struct {
		username string
		password string
		role     api.UserRole
	}{
		{"doctor1", "docpw", api.RoleDoctor},
		{"patient1", "patientpw", api.RolePatient},
		{"patient2", "patient2pw", api.RolePatient},
	} {
		_, create := postJSON(t, apiURL, api.Request{
			Action:         api.ActionCreateUser,
			Token:          hospitalAdminLogin.Token,
			Username:       user.username,
			Password:       user.password,
			Role:           user.role,
			OrganizationID: api.OrgHospital1,
		})
		if !create.Success {
			t.Fatalf("alta de %s fallo: %s", user.username, create.Message)
		}
	}

	_, createResearcher := postJSON(t, apiURL, api.Request{
		Action:         api.ActionCreateUser,
		Token:          researchAdminLogin.Token,
		Username:       "research1",
		Password:       "respw",
		Role:           api.RoleResearcher,
		OrganizationID: api.OrgResearchCenter1,
	})
	if !createResearcher.Success {
		t.Fatalf("alta de research1 fallo: %s", createResearcher.Message)
	}

	_, doctorLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "doctor1",
		Password:       "docpw",
		OrganizationID: api.OrgHospital1,
	})
	if !doctorLogin.Success || doctorLogin.Role != api.RoleDoctor || doctorLogin.OrganizationID != api.OrgHospital1 {
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

	record := api.AnonymizedRecord{
		ID:             "rec-1",
		Classification: "consulta",
		AgeRange:       "18-35",
		Sex:            "F",
		PatientID:      "id1",
		SourceHospital: api.OrgHospital1,
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
		Action:         api.ActionLogin,
		Username:       "research1",
		Password:       "respw",
		OrganizationID: api.OrgResearchCenter1,
	})
	if !researcherLogin.Success || researcherLogin.Role != api.RoleResearcher || researcherLogin.OrganizationID != api.OrgResearchCenter1 {
		t.Fatalf("login investigador fallo: %#v", researcherLogin)
	}

	_, deniedWithoutAgreement := postJSON(t, apiURL, api.Request{
		Action:     api.ActionCreateQueryRequest,
		Token:      researcherLogin.Token,
		HospitalID: api.OrgHospital1,
		Query:      &api.StatsQuery{Classification: "consulta"},
	})
	if deniedWithoutAgreement.Success {
		t.Fatalf("se esperaba rechazo de consulta sin acuerdo previo")
	}

	_, createAgreement := postJSON(t, apiURL, api.Request{
		Action:     api.ActionCreateAgreementRequest,
		Token:      researcherLogin.Token,
		HospitalID: api.OrgHospital1,
	})
	if !createAgreement.Success {
		t.Fatalf("crear acuerdo fallo: %s", createAgreement.Message)
	}

	_, pendingAgreements := postJSON(t, apiURL, api.Request{
		Action:                api.ActionListAgreements,
		Token:                 hospitalAdminLogin.Token,
		AgreementStatusFilter: api.AgreementPending,
	})
	if !pendingAgreements.Success || len(pendingAgreements.Agreements) != 1 {
		t.Fatalf("listado de acuerdos pendientes inesperado: %#v", pendingAgreements)
	}

	_, reviewAgreement := postJSON(t, apiURL, api.Request{
		Action:                api.ActionReviewAgreement,
		Token:                 hospitalAdminLogin.Token,
		AgreementID:           pendingAgreements.Agreements[0].ID,
		AgreementReviewStatus: api.AgreementApproved,
	})
	if !reviewAgreement.Success {
		t.Fatalf("revision de acuerdo fallo: %s", reviewAgreement.Message)
	}

	_, createQuery := postJSON(t, apiURL, api.Request{
		Action:     api.ActionCreateQueryRequest,
		Token:      researcherLogin.Token,
		HospitalID: api.OrgHospital1,
		Query:      &api.StatsQuery{Classification: "consulta"},
	})
	if !createQuery.Success {
		t.Fatalf("crear peticion fallo: %s", createQuery.Message)
	}

	_, pendingQueries := postJSON(t, apiURL, api.Request{
		Action:         api.ActionListQueryRequests,
		Token:          hospitalAdminLogin.Token,
		StatusFilter:   api.QueryPending,
	})
	if !pendingQueries.Success || len(pendingQueries.QueryRequests) != 1 {
		t.Fatalf("listado pendientes inesperado: %#v", pendingQueries)
	}

	_, reviewQuery := postJSON(t, apiURL, api.Request{
		Action:         api.ActionReviewQueryRequest,
		Token:          hospitalAdminLogin.Token,
		QueryID:        pendingQueries.QueryRequests[0].ID,
		ReviewStatus:   api.QueryApproved,
	})
	if !reviewQuery.Success {
		t.Fatalf("revision de consulta fallo: %s", reviewQuery.Message)
	}

	_, approved := postJSON(t, apiURL, api.Request{
		Action:         api.ActionListQueryRequests,
		Token:          researcherLogin.Token,
		OrganizationID: api.OrgResearchCenter1,
		StatusFilter:   api.QueryApproved,
	})
	if !approved.Success || len(approved.QueryRequests) != 1 {
		t.Fatalf("listado aprobado inesperado: %#v", approved)
	}
	if approved.QueryRequests[0].HospitalID != api.OrgHospital1 {
		t.Fatalf("se esperaba hospital1 en la consulta aprobada: %#v", approved.QueryRequests[0])
	}
	if len(approved.QueryRequests[0].StatsRows) != 1 || approved.QueryRequests[0].StatsRows[0].Count != 1 {
		t.Fatalf("estadisticas aprobadas inesperadas: %#v", approved.QueryRequests[0].StatsRows)
	}

	_, patientLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "patient1",
		Password:       "patientpw",
		OrganizationID: api.OrgHospital1,
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
		Action:         api.ActionListQueryRequests,
		Token:          researcherLogin.Token,
		OrganizationID: api.OrgResearchCenter1,
		StatusFilter:   api.QueryApproved,
	})
	if !approvedAfterRevoke.Success || len(approvedAfterRevoke.QueryRequests) != 1 {
		t.Fatalf("listado tras revocacion inesperado: %#v", approvedAfterRevoke)
	}
	if len(approvedAfterRevoke.QueryRequests[0].StatsRows) != 0 {
		t.Fatalf("se esperaban estadisticas vacias tras revocar permiso")
	}
}

func TestServer_AdminScopeIsBoundToOrganization(t *testing.T) {
	ts := newTestHTTPServer(t, 30*time.Minute)
	apiURL := ts.URL + "/api"

	_, hospitalBootstrap := postJSON(t, apiURL, api.Request{
		Action:         api.ActionRegister,
		Username:       "admin-h1",
		Password:       "adminh1pw",
		OrganizationID: api.OrgHospital1,
	})
	if !hospitalBootstrap.Success {
		t.Fatalf("bootstrap hospital fallo: %s", hospitalBootstrap.Message)
	}

	_, centerBootstrap := postJSON(t, apiURL, api.Request{
		Action:         api.ActionRegister,
		Username:       "admin-r1",
		Password:       "adminr1pw",
		OrganizationID: api.OrgResearchCenter1,
	})
	if !centerBootstrap.Success {
		t.Fatalf("bootstrap centro fallo: %s", centerBootstrap.Message)
	}

	_, wrongOrgLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "admin-h1",
		Password:       "adminh1pw",
		OrganizationID: api.OrgHospital2,
	})
	if wrongOrgLogin.Success {
		t.Fatalf("se esperaba rechazo al iniciar sesion en otra organizacion")
	}

	_, hospitalAdminLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "admin-h1",
		Password:       "adminh1pw",
		OrganizationID: api.OrgHospital1,
	})
	if !hospitalAdminLogin.Success {
		t.Fatalf("login admin hospital fallo: %#v", hospitalAdminLogin)
	}

	_, deniedResearcherCreation := postJSON(t, apiURL, api.Request{
		Action:         api.ActionCreateUser,
		Token:          hospitalAdminLogin.Token,
		Username:       "research-bad",
		Password:       "pw",
		Role:           api.RoleResearcher,
		OrganizationID: api.OrgHospital1,
	})
	if deniedResearcherCreation.Success {
		t.Fatalf("se esperaba rechazo al crear un investigador desde un hospital")
	}

	_, deniedCrossOrgCreation := postJSON(t, apiURL, api.Request{
		Action:         api.ActionCreateUser,
		Token:          hospitalAdminLogin.Token,
		Username:       "doctor-bad",
		Password:       "pw",
		Role:           api.RoleDoctor,
		OrganizationID: api.OrgHospital2,
	})
	if deniedCrossOrgCreation.Success {
		t.Fatalf("se esperaba rechazo al crear usuarios fuera de la organizacion del admin")
	}

	_, centerAdminLogin := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "admin-r1",
		Password:       "adminr1pw",
		OrganizationID: api.OrgResearchCenter1,
	})
	if !centerAdminLogin.Success {
		t.Fatalf("login admin centro fallo: %#v", centerAdminLogin)
	}

	_, deniedPatientCreation := postJSON(t, apiURL, api.Request{
		Action:         api.ActionCreateUser,
		Token:          centerAdminLogin.Token,
		Username:       "patient-bad",
		Password:       "pw",
		Role:           api.RolePatient,
		OrganizationID: api.OrgResearchCenter1,
	})
	if deniedPatientCreation.Success {
		t.Fatalf("se esperaba rechazo al crear un paciente desde un centro")
	}

	_, createResearcher := postJSON(t, apiURL, api.Request{
		Action:         api.ActionCreateUser,
		Token:          centerAdminLogin.Token,
		Username:       "research-ok",
		Password:       "pw",
		Role:           api.RoleResearcher,
		OrganizationID: api.OrgResearchCenter1,
	})
	if !createResearcher.Success {
		t.Fatalf("alta de investigador del centro fallo: %#v", createResearcher)
	}
}

func TestServer_MigratesLegacyPatientIdentifiersAndOrganizations(t *testing.T) {
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

	legacyQuery := api.StatsRequest{
		ID:          "legacy-qry",
		RequestedBy: "research1",
		Status:      api.QueryApproved,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := putJSON(db, queriesNamespace, []byte(legacyQuery.ID), legacyQuery); err != nil {
		t.Fatalf("guardando query legacy: %v", err)
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
	if user.OrganizationID != api.OrgHospital1 {
		t.Fatalf("se esperaba migracion de organizacion a hospital1, obtenido %q", user.OrganizationID)
	}

	var migrated api.AnonymizedRecord
	if err := getJSON(db, recordsNamespace, []byte(legacyRecord.ID), &migrated); err != nil {
		t.Fatalf("leyendo registro migrado: %v", err)
	}
	if migrated.PatientID != "id1" || migrated.SourceHospital != api.OrgHospital1 {
		t.Fatalf("registro migrado inesperado: %#v", migrated)
	}

	var migratedQuery api.StatsRequest
	if err := getJSON(db, queriesNamespace, []byte(legacyQuery.ID), &migratedQuery); err != nil {
		t.Fatalf("leyendo query migrada: %v", err)
	}
	if migratedQuery.HospitalID != api.OrgHospital1 {
		t.Fatalf("se esperaba query migrada a hospital1, obtenido %#v", migratedQuery)
	}
}

func TestServer_SessionExpires(t *testing.T) {
	ts := newTestHTTPServer(t, -time.Second)
	apiURL := ts.URL + "/api"

	_, bootstrap := postJSON(t, apiURL, api.Request{
		Action:         api.ActionRegister,
		Username:       "admin",
		Password:       "adminpw",
		OrganizationID: api.OrgHospital1,
	})
	if !bootstrap.Success {
		t.Fatalf("bootstrap fallo: %s", bootstrap.Message)
	}

	_, login := postJSON(t, apiURL, api.Request{
		Action:         api.ActionLogin,
		Username:       "admin",
		Password:       "adminpw",
		OrganizationID: api.OrgHospital1,
	})
	if !login.Success {
		t.Fatalf("login fallo: %s", login.Message)
	}

	_, res := postJSON(t, apiURL, api.Request{
		Action:         api.ActionListQueryRequests,
		Token:          login.Token,
		OrganizationID: api.OrgHospital1,
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
