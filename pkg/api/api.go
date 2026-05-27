// El paquete api contiene las estructuras necesarias
// para la comunicacion entre servidor y cliente.
package api

const (
	ActionRegister               = "register"
	ActionCreateUser             = "createUser"
	ActionValidatePatient        = "validatePatient"
	ActionLogin                  = "login"
	ActionUploadRecord           = "uploadRecord"
	ActionCreateAgreementRequest = "createAgreementRequest"
	ActionListAgreements         = "listAgreements"
	ActionReviewAgreement        = "reviewAgreement"
	ActionCreateQueryRequest     = "createQueryRequest"
	ActionListQueryRequests      = "listQueryRequests"
	ActionReviewQueryRequest     = "reviewQueryRequest"
	ActionSetConsent             = "setConsent"
	ActionLogout                 = "logout"
)

type Request struct {
	Action                string            `json:"action"`
	Username              string            `json:"username,omitempty"`
	Password              string            `json:"password,omitempty"`
	Role                  UserRole          `json:"role,omitempty"`
	Token                 string            `json:"token,omitempty"`
	OrganizationID        string            `json:"organizationId,omitempty"`
	HospitalID            string            `json:"hospitalId,omitempty"`
	AgreementID           string            `json:"agreementId,omitempty"`
	AgreementStatusFilter AgreementStatus   `json:"agreementStatusFilter,omitempty"`
	AgreementReviewStatus AgreementStatus   `json:"agreementReviewStatus,omitempty"`
	AgreementComment      string            `json:"agreementComment,omitempty"`
	Record                *AnonymizedRecord `json:"record,omitempty"`
	Query                 *StatsQuery       `json:"query,omitempty"`
	StatusFilter          QueryStatus       `json:"statusFilter,omitempty"`
	QueryID               string            `json:"queryId,omitempty"`
	ReviewStatus          QueryStatus       `json:"reviewStatus,omitempty"`
	ReviewComment         string            `json:"reviewComment,omitempty"`
	ConsentGranted        *bool             `json:"consentGranted,omitempty"`
}

type Response struct {
	Success         bool           `json:"success"`
	Message         string         `json:"message"`
	Token           string         `json:"token,omitempty"`
	Role            UserRole       `json:"role,omitempty"`
	OrganizationID  string         `json:"organizationId,omitempty"`
	PatientID       string         `json:"patientId,omitempty"`
	RecordsUploaded int            `json:"recordsUploaded,omitempty"`
	Agreements      []Agreement    `json:"agreements,omitempty"`
	StatsRows       []StatsRow     `json:"statsRows,omitempty"`
	QueryRequests   []StatsRequest `json:"queryRequests,omitempty"`
	ConsentGranted  *bool          `json:"consentGranted,omitempty"`
}
