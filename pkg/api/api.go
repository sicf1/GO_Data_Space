// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister           = "register"
	ActionCreateUser         = "createUser"
	ActionValidatePatient    = "validatePatient"
	ActionLogin              = "login"
	ActionUploadRecord       = "uploadRecord"
	ActionCreateQueryRequest = "createQueryRequest"
	ActionListQueryRequests  = "listQueryRequests"
	ActionReviewQueryRequest = "reviewQueryRequest"
	ActionSetConsent         = "setConsent"
	ActionLogout             = "logout"
)

type Request struct {
	Action         string            `json:"action"`
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	Role           UserRole          `json:"role,omitempty"`
	Token          string            `json:"token,omitempty"`
	Record         *AnonymizedRecord `json:"record,omitempty"`
	Query          *StatsQuery       `json:"query,omitempty"`
	StatusFilter   QueryStatus       `json:"statusFilter,omitempty"`
	QueryID        string            `json:"queryId,omitempty"`
	ReviewStatus   QueryStatus       `json:"reviewStatus,omitempty"`
	ReviewComment  string            `json:"reviewComment,omitempty"`
	ConsentGranted *bool             `json:"consentGranted,omitempty"`
}

type Response struct {
	Success         bool           `json:"success"`
	Message         string         `json:"message"`
	Token           string         `json:"token,omitempty"`
	Role            UserRole       `json:"role,omitempty"`
	PatientID       string         `json:"patientId,omitempty"`
	RecordsUploaded int            `json:"recordsUploaded,omitempty"`
	StatsRows       []StatsRow     `json:"statsRows,omitempty"`
	QueryRequests   []StatsRequest `json:"queryRequests,omitempty"`
	ConsentGranted  *bool          `json:"consentGranted,omitempty"`
}
