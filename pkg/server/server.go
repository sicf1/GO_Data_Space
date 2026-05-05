// El paquete server contiene el codigo del servidor.
// Interactua con el cliente mediante una API JSON/HTTPS.
package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"

	"golang.org/x/crypto/argon2"
)

const (
	usersNamespace      = "users"
	sessionsNamespace   = "sessions"
	recordsNamespace    = "records"
	queriesNamespace    = "queries"
	patientIDsNamespace = "patient_ids"
)

type server struct {
	db                 store.Store
	log                *log.Logger
	sessionIdleTimeout time.Duration
}

type userRecord struct {
	Username       string       `json:"username"`
	PasswordSalt   string       `json:"passwordSalt"`
	PasswordHash   string       `json:"passwordHash"`
	Role           api.UserRole `json:"role"`
	PatientID      string       `json:"patientId,omitempty"`
	DataUseAllowed bool         `json:"dataUseAllowed"`
	CreatedAt      string       `json:"createdAt"`
}

type sessionRecord struct {
	Username  string       `json:"username"`
	Role      api.UserRole `json:"role"`
	IssuedAt  string       `json:"issuedAt"`
	LastSeen  string       `json:"lastSeen"`
	ExpiresAt string       `json:"expiresAt"`
}

type legacyStoredRecord struct {
	ID              string `json:"id"`
	Classification  string `json:"classification"`
	AgeRange        string `json:"ageRange"`
	Sex             string `json:"sex"`
	PatientID       string `json:"patientId"`
	PatientUsername string `json:"patientUsername"`
	CreatedAt       string `json:"createdAt"`
	UploadedBy      string `json:"uploadedBy"`
}

type patientUser struct {
	key  []byte
	user userRecord
}

func Run(cfg Config) error {
	cfg = cfg.withDefaults()

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		return fmt.Errorf("error creando la carpeta de datos: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.TLSCertPath), 0755); err != nil {
		return fmt.Errorf("error creando la carpeta TLS: %w", err)
	}
	if err := ensureTLSCertificate(cfg); err != nil {
		return err
	}

	db, err := openSecureStore(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	srv, err := newServer(db, cfg.SessionIdleTimeout)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return httpSrv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
}

func NeedsInitialAdmin(cfg Config) (bool, error) {
	cfg = cfg.withDefaults()

	db, err := openSecureStore(cfg)
	if err != nil {
		return false, err
	}
	defer db.Close()

	return !hasRole(db, api.RoleAdmin), nil
}

func BootstrapInitialAdmin(cfg Config, username, password string) error {
	cfg = cfg.withDefaults()

	db, err := openSecureStore(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	srv, err := newServer(db, cfg.SessionIdleTimeout)
	if err != nil {
		return err
	}
	if hasRole(db, api.RoleAdmin) {
		return nil
	}
	res := srv.registerBootstrapAdmin(username, password)
	if !res.Success {
		return errors.New(res.Message)
	}
	return nil
}

func newServer(db store.Store, timeout time.Duration) (*server, error) {
	srv := &server{
		db:                 db,
		log:                log.New(os.Stdout, "[srv] ", log.LstdFlags),
		sessionIdleTimeout: timeout,
	}
	if err := srv.ensurePatientIdentifiers(); err != nil {
		return nil, err
	}
	return srv, nil
}

func openSecureStore(cfg Config) (store.Store, error) {
	base, err := store.NewStore("bbolt", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("error abriendo base de datos: %w", err)
	}

	salt, err := store.LoadOrCreateSalt(cfg.SaltPath)
	if err != nil {
		_ = base.Close()
		return nil, fmt.Errorf("error cargando la sal maestra: %w", err)
	}
	key := store.DeriveKey(cfg.MasterPassphrase, salt)
	secure, err := store.NewSecureStore(base, key)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	if err := secure.VerifyOrInit(); err != nil {
		_ = secure.Close()
		if errors.Is(err, store.ErrInvalidMasterKey) {
			return nil, fmt.Errorf("clave maestra incorrecta")
		}
		return nil, err
	}
	return secure, nil
}

func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo no permitido", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req api.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerBootstrapAdmin(req.Username, req.Password)
	case api.ActionCreateUser:
		res = s.createUser(req)
	case api.ActionValidatePatient:
		res = s.validatePatient(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionUploadRecord:
		res = s.uploadRecord(req)
	case api.ActionCreateQueryRequest:
		res = s.createQueryRequest(req)
	case api.ActionListQueryRequests:
		res = s.listQueryRequests(req)
	case api.ActionReviewQueryRequest:
		res = s.reviewQueryRequest(req)
	case api.ActionSetConsent:
		res = s.setConsent(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	default:
		res = api.Response{Success: false, Message: "Accion desconocida"}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *server) registerBootstrapAdmin(username, password string) api.Response {
	if hasRole(s.db, api.RoleAdmin) {
		return api.Response{Success: false, Message: "El administrador inicial ya existe"}
	}
	return s.createUserRecord(username, password, api.RoleAdmin)
}

func (s *server) createUser(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok || session.Role != api.RoleAdmin {
		return api.Response{Success: false, Message: "No autorizado para crear usuarios"}
	}
	if req.Role == api.RoleAdmin {
		return api.Response{Success: false, Message: "El alta de administradores no esta permitida desde el menu"}
	}
	return s.createUserRecord(req.Username, req.Password, req.Role)
}

func (s *server) createUserRecord(username, password string, role api.UserRole) api.Response {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	switch role {
	case api.RoleAdmin, api.RoleDoctor, api.RoleResearcher, api.RolePatient:
	default:
		return api.Response{Success: false, Message: "Rol no valido"}
	}

	exists, err := s.userExists(username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return api.Response{Success: false, Message: "Error interno generando credenciales"}
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	now := time.Now().UTC()
	record := userRecord{
		Username:       username,
		PasswordSalt:   base64.StdEncoding.EncodeToString(salt),
		PasswordHash:   base64.StdEncoding.EncodeToString(hash),
		Role:           role,
		DataUseAllowed: true,
		CreatedAt:      now.Format(time.RFC3339),
	}
	if role == api.RolePatient {
		patientID, err := s.allocateNextPatientID()
		if err != nil {
			return api.Response{Success: false, Message: "Error al asignar el identificador anonimizado del paciente"}
		}
		record.PatientID = patientID
	}
	if err := putJSON(s.db, usersNamespace, []byte(username), record); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}
	if record.PatientID != "" {
		if err := s.db.Put(patientIDsNamespace, []byte(record.PatientID), []byte(username)); err != nil {
			_ = s.db.Delete(usersNamespace, []byte(username))
			return api.Response{Success: false, Message: "Error al guardar el identificador anonimizado del paciente"}
		}
	}

	return api.Response{Success: true, Message: "Usuario creado correctamente", Role: role}
}

func (s *server) validatePatient(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if session.Role != api.RoleDoctor && session.Role != api.RoleAdmin {
		return api.Response{Success: false, Message: "No autorizado para validar pacientes"}
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		return api.Response{Success: false, Message: "Falta el usuario del paciente"}
	}

	patient, err := s.loadUser(username)
	if err != nil || patient.Role != api.RolePatient {
		return api.Response{Success: false, Message: "El paciente indicado no existe"}
	}
	if patient.PatientID == "" {
		return api.Response{Success: false, Message: "El paciente no tiene identificador anonimizado asignado"}
	}
	return api.Response{Success: true, Message: "Paciente valido", PatientID: patient.PatientID}
}

func (s *server) loginUser(req api.Request) api.Response {
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if username == "" || password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	user, err := s.loadUser(username)
	if err != nil || !verifyPassword(user, password) {
		return api.Response{Success: false, Message: "Credenciales invalidas"}
	}

	token, err := generateSessionToken()
	if err != nil {
		return api.Response{Success: false, Message: "Error interno de sesion"}
	}
	now := time.Now().UTC()
	session := sessionRecord{
		Username:  username,
		Role:      user.Role,
		IssuedAt:  now.Format(time.RFC3339),
		LastSeen:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(s.sessionIdleTimeout).Format(time.RFC3339),
	}
	if err := putJSON(s.db, sessionsNamespace, []byte(sessionKey(token)), session); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesion"}
	}

	res := api.Response{
		Success: true,
		Message: "Login exitoso",
		Token:   token,
		Role:    user.Role,
	}
	if user.Role == api.RolePatient {
		consent := user.DataUseAllowed
		res.ConsentGranted = &consent
	}
	return res
}

func (s *server) uploadRecord(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if session.Role != api.RoleDoctor {
		return api.Response{Success: false, Message: "Solo un medico puede introducir datos de paciente"}
	}
	if req.Record == nil {
		return api.Response{Success: false, Message: "Falta el registro anonimizado"}
	}
	if err := req.Record.Validate(); err != nil {
		return api.Response{Success: false, Message: "Registro invalido"}
	}
	if req.Record.UploadedBy != session.Username {
		return api.Response{Success: false, Message: "El registro no pertenece al medico autenticado"}
	}

	patient, err := s.loadPatientByID(req.Record.PatientID)
	if err != nil || patient.Role != api.RolePatient {
		return api.Response{Success: false, Message: "El paciente indicado no existe"}
	}

	if err := putJSON(s.db, recordsNamespace, []byte(req.Record.ID), req.Record); err != nil {
		return api.Response{Success: false, Message: "Error al guardar el registro"}
	}
	return api.Response{
		Success:         true,
		Message:         "Registro anonimizado subido correctamente",
		RecordsUploaded: 1,
	}
}

func (s *server) createQueryRequest(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if session.Role != api.RoleResearcher {
		return api.Response{Success: false, Message: "Solo un investigador puede pedir consultas"}
	}

	query := api.StatsQuery{}
	if req.Query != nil {
		query = *req.Query
	}
	if query.Classification != "" {
		normalized, err := api.NormalizeClassification(query.Classification)
		if err != nil {
			return api.Response{Success: false, Message: "Clasificacion no valida"}
		}
		query.Classification = normalized
	}
	if query.AgeRange != "" && ageRangeOrder(query.AgeRange) == 99 {
		return api.Response{Success: false, Message: "Rango de edad no valido"}
	}

	request := api.StatsRequest{
		ID:             generateIdentifier("qry"),
		Classification: query.Classification,
		AgeRange:       query.AgeRange,
		RequestedBy:    session.Username,
		Status:         api.QueryPending,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	if err := putJSON(s.db, queriesNamespace, []byte(request.ID), request); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la peticion"}
	}
	return api.Response{Success: true, Message: "Peticion de consulta registrada"}
}

func (s *server) listQueryRequests(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if session.Role != api.RoleAdmin && session.Role != api.RoleResearcher {
		return api.Response{Success: false, Message: "No autorizado para consultar peticiones"}
	}

	keys, err := s.db.ListKeys(queriesNamespace)
	if err != nil && !errors.Is(err, store.ErrNamespaceNotFound) {
		return api.Response{Success: false, Message: "Error al leer peticiones"}
	}

	var requests []api.StatsRequest
	for _, key := range keys {
		var query api.StatsRequest
		if err := getJSON(s.db, queriesNamespace, key, &query); err != nil {
			return api.Response{Success: false, Message: "Error al procesar peticiones"}
		}
		if session.Role == api.RoleResearcher && query.RequestedBy != session.Username {
			continue
		}
		if req.StatusFilter != "" && query.Status != req.StatusFilter {
			continue
		}
		if session.Role == api.RoleResearcher && query.Status == api.QueryApproved {
			rows, err := s.computeStats(query)
			if err != nil {
				return api.Response{Success: false, Message: "Error al generar estadisticas"}
			}
			query.StatsRows = rows
		}
		requests = append(requests, query)
	}

	sort.Slice(requests, func(i, j int) bool {
		return requests[i].CreatedAt > requests[j].CreatedAt
	})
	return api.Response{
		Success:       true,
		Message:       "Peticiones recuperadas correctamente",
		QueryRequests: requests,
	}
}

func (s *server) reviewQueryRequest(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if session.Role != api.RoleAdmin {
		return api.Response{Success: false, Message: "Solo un administrador puede revisar peticiones"}
	}
	if strings.TrimSpace(req.QueryID) == "" {
		return api.Response{Success: false, Message: "Falta el identificador de la peticion"}
	}
	if req.ReviewStatus != api.QueryApproved && req.ReviewStatus != api.QueryDenied {
		return api.Response{Success: false, Message: "Estado de revision no valido"}
	}

	var query api.StatsRequest
	if err := getJSON(s.db, queriesNamespace, []byte(req.QueryID), &query); err != nil {
		return api.Response{Success: false, Message: "La peticion no existe"}
	}
	if query.Status != api.QueryPending {
		return api.Response{Success: false, Message: "La peticion ya fue revisada"}
	}

	query.Status = req.ReviewStatus
	query.ReviewedBy = session.Username
	query.ReviewedAt = time.Now().UTC().Format(time.RFC3339)
	query.ReviewComment = strings.TrimSpace(req.ReviewComment)
	if err := putJSON(s.db, queriesNamespace, []byte(query.ID), query); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar la peticion"}
	}
	return api.Response{Success: true, Message: "Peticion revisada correctamente"}
}

func (s *server) setConsent(req api.Request) api.Response {
	session, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if session.Role != api.RolePatient {
		return api.Response{Success: false, Message: "Solo un paciente puede modificar este permiso"}
	}
	if req.ConsentGranted == nil {
		return api.Response{Success: false, Message: "Falta indicar el nuevo estado del permiso"}
	}

	user, err := s.loadUser(session.Username)
	if err != nil {
		return api.Response{Success: false, Message: "No se ha podido cargar el usuario"}
	}
	user.DataUseAllowed = *req.ConsentGranted
	if err := putJSON(s.db, usersNamespace, []byte(user.Username), user); err != nil {
		return api.Response{Success: false, Message: "No se ha podido actualizar el permiso"}
	}
	consent := user.DataUseAllowed
	return api.Response{
		Success:        true,
		Message:        "Permiso de uso de datos actualizado",
		ConsentGranted: &consent,
	}
}

func (s *server) logoutUser(req api.Request) api.Response {
	_, ok := s.authenticate(req.Token)
	if !ok {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if err := s.db.Delete(sessionsNamespace, []byte(sessionKey(req.Token))); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesion"}
	}
	return api.Response{Success: true, Message: "Sesion cerrada correctamente"}
}

func (s *server) computeStats(query api.StatsRequest) ([]api.StatsRow, error) {
	keys, err := s.db.ListKeys(recordsNamespace)
	if err != nil && !errors.Is(err, store.ErrNamespaceNotFound) {
		return nil, err
	}

	counts := make(map[string]int)
	for _, key := range keys {
		var record api.AnonymizedRecord
		if err := getJSON(s.db, recordsNamespace, key, &record); err != nil {
			return nil, err
		}
		patient, err := s.loadPatientByID(record.PatientID)
		if err != nil || patient.Role != api.RolePatient || !patient.DataUseAllowed {
			continue
		}
		if query.Classification != "" && record.Classification != query.Classification {
			continue
		}
		if query.AgeRange != "" && record.AgeRange != query.AgeRange {
			continue
		}
		groupKey := record.Classification + "|" + record.AgeRange
		counts[groupKey]++
	}

	rows := make([]api.StatsRow, 0, len(counts))
	for key, count := range counts {
		parts := strings.SplitN(key, "|", 2)
		rows = append(rows, api.StatsRow{
			Classification: parts[0],
			AgeRange:       parts[1],
			Count:          count,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Classification == rows[j].Classification {
			return ageRangeOrder(rows[i].AgeRange) < ageRangeOrder(rows[j].AgeRange)
		}
		return rows[i].Classification < rows[j].Classification
	})
	return rows, nil
}

func (s *server) authenticate(token string) (sessionRecord, bool) {
	if strings.TrimSpace(token) == "" {
		return sessionRecord{}, false
	}
	session, err := s.loadSession(token)
	if err != nil {
		return sessionRecord{}, false
	}

	expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || time.Now().UTC().After(expiresAt) {
		_ = s.db.Delete(sessionsNamespace, []byte(sessionKey(token)))
		return sessionRecord{}, false
	}

	now := time.Now().UTC()
	session.LastSeen = now.Format(time.RFC3339)
	session.ExpiresAt = now.Add(s.sessionIdleTimeout).Format(time.RFC3339)
	if err := putJSON(s.db, sessionsNamespace, []byte(sessionKey(token)), session); err != nil {
		return sessionRecord{}, false
	}
	return session, true
}

func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get(usersNamespace, []byte(username))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
		return false, nil
	}
	return false, err
}

func (s *server) loadUser(username string) (userRecord, error) {
	var user userRecord
	if err := getJSON(s.db, usersNamespace, []byte(username), &user); err != nil {
		return userRecord{}, err
	}
	return user, nil
}

func (s *server) loadSession(token string) (sessionRecord, error) {
	var session sessionRecord
	if err := getJSON(s.db, sessionsNamespace, []byte(sessionKey(token)), &session); err != nil {
		return sessionRecord{}, err
	}
	return session, nil
}

func (s *server) loadPatientByID(patientID string) (userRecord, error) {
	username, err := s.findUsernameByPatientID(patientID)
	if err != nil {
		return userRecord{}, err
	}
	return s.loadUser(username)
}

func (s *server) findUsernameByPatientID(patientID string) (string, error) {
	patientID = strings.TrimSpace(patientID)
	if patientID == "" {
		return "", store.ErrKeyNotFound
	}

	raw, err := s.db.Get(patientIDsNamespace, []byte(patientID))
	if err == nil {
		return string(raw), nil
	}
	if !errors.Is(err, store.ErrNamespaceNotFound) && !errors.Is(err, store.ErrKeyNotFound) {
		return "", err
	}

	keys, err := s.db.ListKeys(usersNamespace)
	if err != nil {
		return "", err
	}
	for _, key := range keys {
		var user userRecord
		if err := getJSON(s.db, usersNamespace, key, &user); err != nil {
			continue
		}
		if user.Role == api.RolePatient && user.PatientID == patientID {
			_ = s.db.Put(patientIDsNamespace, []byte(patientID), []byte(user.Username))
			return user.Username, nil
		}
	}
	return "", store.ErrKeyNotFound
}

func (s *server) ensurePatientIdentifiers() error {
	keys, err := s.db.ListKeys(usersNamespace)
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			return nil
		}
		return err
	}

	usersByUsername := make(map[string]userRecord, len(keys))
	patientsWithoutID := make([]patientUser, 0)
	maxPatientIndex := 0

	for _, key := range keys {
		var user userRecord
		if err := getJSON(s.db, usersNamespace, key, &user); err != nil {
			return err
		}
		usersByUsername[user.Username] = user
		if user.Role != api.RolePatient {
			continue
		}
		if idx, ok := parsePatientID(user.PatientID); ok && idx > maxPatientIndex {
			maxPatientIndex = idx
		}
		if strings.TrimSpace(user.PatientID) == "" {
			patientsWithoutID = append(patientsWithoutID, patientUser{key: key, user: user})
			continue
		}
		if err := s.db.Put(patientIDsNamespace, []byte(user.PatientID), []byte(user.Username)); err != nil {
			return err
		}
	}

	sort.Slice(patientsWithoutID, func(i, j int) bool {
		if patientsWithoutID[i].user.CreatedAt == patientsWithoutID[j].user.CreatedAt {
			return patientsWithoutID[i].user.Username < patientsWithoutID[j].user.Username
		}
		return patientsWithoutID[i].user.CreatedAt < patientsWithoutID[j].user.CreatedAt
	})

	for _, patient := range patientsWithoutID {
		maxPatientIndex++
		patient.user.PatientID = formatPatientID(maxPatientIndex)
		if err := putJSON(s.db, usersNamespace, patient.key, patient.user); err != nil {
			return err
		}
		if err := s.db.Put(patientIDsNamespace, []byte(patient.user.PatientID), []byte(patient.user.Username)); err != nil {
			return err
		}
		usersByUsername[patient.user.Username] = patient.user
	}

	return s.migrateLegacyRecords(usersByUsername)
}

func (s *server) migrateLegacyRecords(usersByUsername map[string]userRecord) error {
	keys, err := s.db.ListKeys(recordsNamespace)
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			return nil
		}
		return err
	}

	for _, key := range keys {
		raw, err := s.db.Get(recordsNamespace, key)
		if err != nil {
			return err
		}

		var legacy legacyStoredRecord
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return err
		}

		if strings.TrimSpace(legacy.PatientID) != "" && strings.TrimSpace(legacy.PatientUsername) == "" {
			continue
		}

		if strings.TrimSpace(legacy.PatientID) == "" {
			patient, ok := usersByUsername[strings.TrimSpace(legacy.PatientUsername)]
			if !ok || patient.Role != api.RolePatient || patient.PatientID == "" {
				continue
			}
			legacy.PatientID = patient.PatientID
		}

		record := api.AnonymizedRecord{
			ID:             legacy.ID,
			Classification: legacy.Classification,
			AgeRange:       legacy.AgeRange,
			Sex:            legacy.Sex,
			PatientID:      legacy.PatientID,
			CreatedAt:      legacy.CreatedAt,
			UploadedBy:     legacy.UploadedBy,
		}
		if err := record.Validate(); err != nil {
			return err
		}
		if err := putJSON(s.db, recordsNamespace, key, record); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) allocateNextPatientID() (string, error) {
	keys, err := s.db.ListKeys(usersNamespace)
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			return formatPatientID(1), nil
		}
		return "", err
	}

	maxPatientIndex := 0
	for _, key := range keys {
		var user userRecord
		if err := getJSON(s.db, usersNamespace, key, &user); err != nil {
			return "", err
		}
		if user.Role != api.RolePatient {
			continue
		}
		if idx, ok := parsePatientID(user.PatientID); ok && idx > maxPatientIndex {
			maxPatientIndex = idx
		}
	}
	return formatPatientID(maxPatientIndex + 1), nil
}

func hasRole(db store.Store, role api.UserRole) bool {
	keys, err := db.ListKeys(usersNamespace)
	if err != nil {
		return false
	}
	for _, key := range keys {
		var user userRecord
		if err := getJSON(db, usersNamespace, key, &user); err == nil && user.Role == role {
			return true
		}
	}
	return false
}

func verifyPassword(user userRecord, password string) bool {
	salt, err := base64.StdEncoding.DecodeString(user.PasswordSalt)
	if err != nil {
		return false
	}
	storedHash, err := base64.StdEncoding.DecodeString(user.PasswordHash)
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(computed, storedHash) == 1
}

func generateSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateIdentifier(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixNano(), hex.EncodeToString(buf))
}

func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func putJSON(db store.Store, namespace string, key []byte, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return db.Put(namespace, key, raw)
}

func getJSON(db store.Store, namespace string, key []byte, dest any) error {
	raw, err := db.Get(namespace, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

func parsePatientID(patientID string) (int, bool) {
	patientID = strings.TrimSpace(patientID)
	if !strings.HasPrefix(patientID, "id") {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimPrefix(patientID, "id"))
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}

func formatPatientID(index int) string {
	return fmt.Sprintf("id%d", index)
}

func ageRangeOrder(ageRange string) int {
	switch ageRange {
	case "0-17":
		return 0
	case "18-35":
		return 1
	case "36-50":
		return 2
	case "51-65":
		return 3
	case "66+":
		return 4
	default:
		return 99
	}
}

func ensureTLSCertificate(cfg Config) error {
	if _, err := os.Stat(cfg.TLSCertPath); err == nil {
		if _, err := os.Stat(cfg.TLSKeyPath); err == nil {
			return nil
		}
	}

	certPEM, keyPEM, err := generateSelfSignedCertificate()
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.TLSCertPath, certPEM, 0600); err != nil {
		return fmt.Errorf("no se ha podido guardar el certificado TLS: %w", err)
	}
	if err := os.WriteFile(cfg.TLSKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("no se ha podido guardar la clave TLS: %w", err)
	}
	return nil
}

func generateSelfSignedCertificate() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("no se ha podido generar la clave privada TLS: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 62)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("no se ha podido generar el serial TLS: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "sprout-localhost",
			Organization: []string{"sprout"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("no se ha podido generar el certificado TLS: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM, nil
}
