// El paquete client contiene la logica de interaccion con el usuario
// asi como de comunicacion con el servidor.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"
	"sprout/pkg/ui"
)

type client struct {
	log            *log.Logger
	serverURL      string
	profileLabel   string
	currentUser    string
	currentRole    api.UserRole
	authToken      string
	consentGranted *bool
	httpClient     *http.Client
	localStore     store.Store
	exitRequested  bool
}

func Run(cfg Config) error {
	httpClient, err := newHTTPSClient(cfg.TLSCertPath)
	if err != nil {
		return err
	}
	localStore, err := openLocalStore(cfg)
	if err != nil {
		return err
	}
	defer localStore.Close()

	c := &client{
		log:          log.New(os.Stdout, "[cli] ", log.LstdFlags),
		serverURL:    cfg.ServerURL,
		profileLabel: cfg.ProfileLabel,
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: httpClient.Transport,
		},
		localStore: localStore,
	}
	c.runLoop()
	return nil
}

func newHTTPSClient(certPath string) (*http.Client, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("no se ha podido leer el certificado del servidor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("no se ha podido cargar el certificado del servidor")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		},
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: transport}, nil
}

func (c *client) runLoop() {
	for {
		if c.exitRequested {
			return
		}
		ui.ClearScreen()

		if c.currentUser == "" {
			switch ui.PrintMenu(c.menuTitle("Inicio"), []string{
				"Iniciar sesion",
				"Salir",
			}) {
			case 1:
				c.loginUser()
			case 2:
				c.log.Printf("Saliendo de %s...\n", c.profileLabel)
				c.exitRequested = true
			}
			ui.Pause("Pulsa [Enter] para continuar...")
			continue
		}

		switch c.currentRole {
		case api.RoleAdmin:
			c.runAdminMenu()
		case api.RoleDoctor:
			c.runDoctorMenu()
		case api.RoleResearcher:
			c.runResearcherMenu()
		case api.RolePatient:
			c.runPatientMenu()
		default:
			fmt.Println("Rol no reconocido. Cerrando sesion.")
			c.clearSession()
			ui.Pause("Pulsa [Enter] para continuar...")
		}
	}
}

func (c *client) runAdminMenu() {
	switch ui.PrintMenu(c.menuTitle(fmt.Sprintf("Administrador (%s)", c.currentUser)), []string{
		"Autorizar peticion",
		"Dar de alta medico",
		"Dar de alta investigador",
		"Dar de alta paciente",
		"Cerrar sesion",
		"Salir",
	}) {
	case 1:
		c.reviewPendingQuery()
	case 2:
		c.createUser(api.RoleDoctor)
	case 3:
		c.createUser(api.RoleResearcher)
	case 4:
		c.createUser(api.RolePatient)
	case 5:
		c.logoutUser()
	case 6:
		c.log.Printf("Saliendo de %s...\n", c.profileLabel)
		c.exitRequested = true
	}
	ui.Pause("Pulsa [Enter] para continuar...")
}

func (c *client) runDoctorMenu() {
	switch ui.PrintMenu(c.menuTitle(fmt.Sprintf("Medico (%s)", c.currentUser)), []string{
		"Introducir datos de paciente",
		"Listar registros locales",
		"Subir registro anonimizado",
		"Cerrar sesion",
		"Salir",
	}) {
	case 1:
		c.createLocalRecord()
	case 2:
		c.listLocalRecords()
	case 3:
		c.uploadLocalRecord()
	case 4:
		c.logoutUser()
	case 5:
		c.log.Printf("Saliendo de %s...\n", c.profileLabel)
		c.exitRequested = true
	}
	ui.Pause("Pulsa [Enter] para continuar...")
}

func (c *client) runResearcherMenu() {
	switch ui.PrintMenu(c.menuTitle(fmt.Sprintf("Investigador (%s)", c.currentUser)), []string{
		"Hacer peticion de consulta de datos",
		"Ver consultas aprobadas",
		"Ver consultas denegadas",
		"Cerrar sesion",
		"Salir",
	}) {
	case 1:
		c.createQueryRequest()
	case 2:
		c.listQueries(api.QueryApproved)
	case 3:
		c.listQueries(api.QueryDenied)
	case 4:
		c.logoutUser()
	case 5:
		c.log.Printf("Saliendo de %s...\n", c.profileLabel)
		c.exitRequested = true
	}
	ui.Pause("Pulsa [Enter] para continuar...")
}

func (c *client) runPatientMenu() {
	actionLabel := "Revocar permisos uso de datos"
	if c.consentGranted != nil && !*c.consentGranted {
		actionLabel = "Restablecer permisos uso de datos"
	}
	switch ui.PrintMenu(c.menuTitle(fmt.Sprintf("Paciente (%s)", c.currentUser)), []string{
		actionLabel,
		"Cerrar sesion",
		"Salir",
	}) {
	case 1:
		c.toggleConsent()
	case 2:
		c.logoutUser()
	case 3:
		c.log.Printf("Saliendo de %s...\n", c.profileLabel)
		c.exitRequested = true
	}
	ui.Pause("Pulsa [Enter] para continuar...")
}

func (c *client) createUser(role api.UserRole) {
	ui.ClearScreen()
	fmt.Printf("** Alta de %s en %s **\n", role, c.profileLabel)
	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contrasena")
	if err != nil {
		c.log.Println("No se ha podido leer la contrasena:", err)
		return
	}
	res := c.sendRequest(api.Request{
		Action:   api.ActionCreateUser,
		Username: username,
		Password: password,
		Role:     role,
		Token:    c.authToken,
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Printf("** Inicio de sesion en %s **\n", c.profileLabel)

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contrasena")
	if err != nil {
		c.log.Println("No se ha podido leer la contrasena:", err)
		return
	}
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		return
	}
	c.currentUser = username
	c.currentRole = res.Role
	c.authToken = res.Token
	c.consentGranted = res.ConsentGranted
}

func (c *client) logoutUser() {
	res := c.sendRequest(api.Request{
		Action: api.ActionLogout,
		Token:  c.authToken,
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		c.clearSession()
	}
}

func (c *client) clearSession() {
	c.currentUser = ""
	c.currentRole = ""
	c.authToken = ""
	c.consentGranted = nil
}

func (c *client) createLocalRecord() {
	ui.ClearScreen()
	fmt.Printf("** Introducir datos de paciente en %s **\n", c.profileLabel)
	fmt.Println("Clasificaciones disponibles:", shortClassificationOptions())
	fmt.Println("Sexos permitidos: M, F, X, ND")

	patientUsername := ui.ReadInput("Usuario paciente")
	patientID, ok := c.lookupPatientID(patientUsername)
	if !ok {
		return
	}

	input := api.RecordInput{
		PatientID:       patientID,
		PatientUsername: patientUsername,
		Classification:  ui.ReadInput("Clasificacion"),
		Age:             ui.ReadInt("Edad del paciente"),
		Sex:             ui.ReadInput("Sexo"),
		PatientAlias:    ui.ReadInput("Alias local del paciente"),
		Observation:     ui.ReadMultiline("Observaciones medicas"),
	}
	record, err := api.NewLocalRecord(input, c.currentUser, time.Now())
	if err != nil {
		fmt.Println("No se ha podido armonizar el registro:", err)
		return
	}
	if err := storeLocalRecord(c.localStore, record); err != nil {
		fmt.Println("No se ha podido guardar el registro local:", err)
		return
	}
	fmt.Printf("Registro local guardado con ID=%s y paciente anonimizado=%s\n", record.ID, record.PatientID)
}

func (c *client) lookupPatientID(username string) (string, bool) {
	res := c.sendRequest(api.Request{
		Action:   api.ActionValidatePatient,
		Token:    c.authToken,
		Username: username,
	})
	if res.Success {
		return res.PatientID, true
	}
	fmt.Println("No se puede crear el registro:", res.Message)
	return "", false
}

func (c *client) listLocalRecords() {
	ui.ClearScreen()
	fmt.Printf("** Registros locales de %s **\n", c.profileLabel)

	records, err := listLocalRecords(c.localStore, c.currentUser)
	if err != nil {
		fmt.Println("Error al listar los registros:", err)
		return
	}
	if len(records) == 0 {
		fmt.Println("No hay registros locales guardados.")
		return
	}
	for i, record := range records {
		fmt.Printf("%d. ID=%s | paciente=%s | usuario=%s | clasificacion=%s | rango=%s | sexo=%s\n",
			i+1, record.ID, record.PatientID, record.PatientUsername, record.Classification, record.AgeRange, record.Sex)
	}
}

func (c *client) uploadLocalRecord() {
	ui.ClearScreen()
	fmt.Println("** Subir registro anonimizado **")

	records, err := listLocalRecords(c.localStore, c.currentUser)
	if err != nil {
		fmt.Println("Error al cargar los registros locales:", err)
		return
	}
	if len(records) == 0 {
		fmt.Println("No hay registros locales para subir.")
		return
	}

	options := make([]string, 0, len(records))
	for _, record := range records {
		options = append(options, fmt.Sprintf("%s | paciente=%s | %s | %s",
			record.ID, emptyLabel(record.PatientID, "sin-id"), record.Classification, record.AgeRange))
	}
	choice := ui.PrintMenu("Selecciona un registro", options)
	selected := records[choice-1]

	if strings.TrimSpace(selected.PatientID) == "" {
		patientID, ok := c.lookupPatientID(selected.PatientUsername)
		if !ok {
			return
		}
		selected.PatientID = patientID
		if err := storeLocalRecord(c.localStore, selected); err != nil {
			fmt.Println("No se ha podido actualizar el identificador anonimizado local:", err)
			return
		}
	}

	res := c.sendRequest(api.Request{
		Action: api.ActionUploadRecord,
		Token:  c.authToken,
		Record: ptrAnonymized(selected.ToAnonymized()),
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

func (c *client) createQueryRequest() {
	ui.ClearScreen()
	fmt.Println("** Nueva peticion de consulta **")
	fmt.Println("Deja vacios los filtros para consultar todo el conjunto disponible.")
	fmt.Println("Clasificaciones disponibles:", shortClassificationOptions())
	fmt.Println("Rangos de edad: 0-17, 18-35, 36-50, 51-65, 66+")

	classification := strings.TrimSpace(ui.ReadInput("Filtrar por clasificacion"))
	ageRange := strings.TrimSpace(ui.ReadInput("Filtrar por rango de edad"))
	var query *api.StatsQuery
	if classification != "" || ageRange != "" {
		query = &api.StatsQuery{Classification: classification, AgeRange: ageRange}
	}
	res := c.sendRequest(api.Request{
		Action: api.ActionCreateQueryRequest,
		Token:  c.authToken,
		Query:  query,
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

func (c *client) listQueries(status api.QueryStatus) {
	ui.ClearScreen()
	fmt.Printf("** Consultas %s **\n", status)
	res := c.sendRequest(api.Request{
		Action:       api.ActionListQueryRequests,
		Token:        c.authToken,
		StatusFilter: status,
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		return
	}
	if len(res.QueryRequests) == 0 {
		fmt.Println("No hay consultas en ese estado.")
		return
	}
	for _, query := range res.QueryRequests {
		fmt.Printf("- %s | clasificacion=%s | rango=%s | estado=%s\n",
			query.ID, emptyLabel(query.Classification, "todas"), emptyLabel(query.AgeRange, "todos"), query.Status)
		if query.ReviewComment != "" {
			fmt.Println("  Comentario:", query.ReviewComment)
		}
		for _, row := range query.StatsRows {
			fmt.Printf("  %s | %s -> %d\n", row.Classification, row.AgeRange, row.Count)
		}
	}
}

func (c *client) reviewPendingQuery() {
	ui.ClearScreen()
	fmt.Println("** Autorizar o denegar peticion **")

	res := c.sendRequest(api.Request{
		Action:       api.ActionListQueryRequests,
		Token:        c.authToken,
		StatusFilter: api.QueryPending,
	})
	if !res.Success {
		fmt.Println("Error:", res.Message)
		return
	}
	if len(res.QueryRequests) == 0 {
		fmt.Println("No hay peticiones pendientes.")
		return
	}

	options := make([]string, 0, len(res.QueryRequests))
	for _, query := range res.QueryRequests {
		options = append(options, fmt.Sprintf("%s | investigador=%s | clasificacion=%s | rango=%s",
			query.ID, query.RequestedBy, emptyLabel(query.Classification, "todas"), emptyLabel(query.AgeRange, "todos")))
	}
	choice := ui.PrintMenu("Selecciona una peticion", options)
	selected := res.QueryRequests[choice-1]

	approve := ui.Confirm("Aprobar la peticion seleccionada?")
	status := api.QueryDenied
	if approve {
		status = api.QueryApproved
	}
	comment := ui.ReadInput("Comentario de revision")
	reviewRes := c.sendRequest(api.Request{
		Action:        api.ActionReviewQueryRequest,
		Token:         c.authToken,
		QueryID:       selected.ID,
		ReviewStatus:  status,
		ReviewComment: comment,
	})
	fmt.Println("Exito:", reviewRes.Success)
	fmt.Println("Mensaje:", reviewRes.Message)
}

func (c *client) toggleConsent() {
	ui.ClearScreen()
	fmt.Println("** Permiso de uso de datos **")

	newValue := true
	if c.consentGranted == nil || *c.consentGranted {
		newValue = false
	}
	res := c.sendRequest(api.Request{
		Action:         api.ActionSetConsent,
		Token:          c.authToken,
		ConsentGranted: &newValue,
	})
	fmt.Println("Exito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		c.consentGranted = res.ConsentGranted
	}
}

func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, err := json.Marshal(req)
	if err != nil {
		c.log.Println("No se ha podido serializar la peticion JSON:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		c.log.Println("No se ha podido construir la peticion HTTPS:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return api.Response{Success: false, Message: "Error de conexion"}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.log.Println("No se ha podido leer la respuesta:", err)
		return api.Response{Success: false, Message: "Respuesta invalida del servidor"}
	}
	var res api.Response
	if err := json.Unmarshal(body, &res); err != nil {
		c.log.Println("No se ha podido descodificar la respuesta JSON:", err)
		return api.Response{Success: false, Message: "Respuesta invalida del servidor"}
	}
	return res
}

func (c *client) menuTitle(section string) string {
	return fmt.Sprintf("%s\nEntidad: %s", section, c.profileLabel)
}

func ptrAnonymized(record api.AnonymizedRecord) *api.AnonymizedRecord {
	return &record
}

func emptyLabel(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
