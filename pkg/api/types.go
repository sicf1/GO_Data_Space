package api

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

type UserRole string

const (
	RoleAdmin      UserRole = "admin"
	RoleDoctor     UserRole = "doctor"
	RoleResearcher UserRole = "researcher"
	RolePatient    UserRole = "patient"
)

const (
	OrgPlatform             = "platform"
	OrgHospital1            = "hospital1"
	OrgHospital2            = "hospital2"
	OrgHospital3            = "hospital3"
	OrgResearchCenter1      = "centro_investigacion1"
	OrgResearchCenter1Label = "centro de investigacion1"
)

var HospitalOrganizations = []string{
	OrgHospital1,
	OrgHospital2,
	OrgHospital3,
}

var ResearchCenterOrganizations = []string{
	OrgResearchCenter1,
}

var KnownOrganizations = []string{
	OrgPlatform,
	OrgHospital1,
	OrgHospital2,
	OrgHospital3,
	OrgResearchCenter1,
}

type QueryStatus string

const (
	QueryPending  QueryStatus = "pending"
	QueryApproved QueryStatus = "approved"
	QueryDenied   QueryStatus = "denied"
)

type AgreementStatus string

const (
	AgreementPending  AgreementStatus = "pending"
	AgreementApproved AgreementStatus = "approved"
	AgreementDenied   AgreementStatus = "denied"
)

var SupportedClassifications = []string{
	"consulta",
	"urgencia",
	"hospitalizacion",
	"analitica",
	"imagen",
}

var SupportedSexValues = []string{"M", "F", "X", "ND"}

type RecordInput struct {
	Classification  string
	Age             int
	Sex             string
	PatientID       string
	PatientUsername string
	PatientAlias    string
	Observation     string
	SourceHospital  string
}

type LocalRecord struct {
	XMLName         xml.Name `xml:"healthRecord" json:"-"`
	ID              string   `xml:"id" json:"id"`
	Classification  string   `xml:"classification" json:"classification"`
	AgeRange        string   `xml:"ageRange" json:"ageRange"`
	Sex             string   `xml:"sex" json:"sex"`
	PatientID       string   `xml:"patientId" json:"patientId"`
	PatientUsername string   `xml:"patientUsername" json:"patientUsername"`
	PatientAlias    string   `xml:"patientAlias" json:"patientAlias"`
	Observation     string   `xml:"observation" json:"observation"`
	SourceHospital  string   `xml:"sourceHospital" json:"sourceHospital"`
	CreatedAt       string   `xml:"createdAt" json:"createdAt"`
	UploadedBy      string   `xml:"uploadedBy" json:"uploadedBy"`
}

type AnonymizedRecord struct {
	ID             string `json:"id"`
	Classification string `json:"classification"`
	AgeRange       string `json:"ageRange"`
	Sex            string `json:"sex"`
	PatientID      string `json:"patientId"`
	SourceHospital string `json:"sourceHospital"`
	CreatedAt      string `json:"createdAt"`
	UploadedBy     string `json:"uploadedBy"`
}

type StatsQuery struct {
	Classification string `json:"classification,omitempty"`
	AgeRange       string `json:"ageRange,omitempty"`
}

type StatsRow struct {
	Classification string `json:"classification"`
	AgeRange       string `json:"ageRange"`
	Count          int    `json:"count"`
}

type HospitalStatsBlock struct {
	HospitalID string     `json:"hospitalId"`
	Rows       []StatsRow `json:"rows"`
}

type Agreement struct {
	ID               string          `json:"id"`
	HospitalID       string          `json:"hospitalId"`
	ResearchCenterID string          `json:"researchCenterId"`
	RequestedBy      string          `json:"requestedBy"`
	Status           AgreementStatus `json:"status"`
	CreatedAt        string          `json:"createdAt"`
	ReviewedBy       string          `json:"reviewedBy,omitempty"`
	ReviewedAt       string          `json:"reviewedAt,omitempty"`
	ReviewComment    string          `json:"reviewComment,omitempty"`
}

type StatsRequest struct {
	ID             string      `json:"id"`
	HospitalID     string      `json:"hospitalId"`
	AgreementID    string      `json:"agreementId,omitempty"`
	Classification string      `json:"classification,omitempty"`
	AgeRange       string      `json:"ageRange,omitempty"`
	RequestedBy    string      `json:"requestedBy"`
	Status         QueryStatus `json:"status"`
	CreatedAt      string      `json:"createdAt"`
	ReviewedBy     string      `json:"reviewedBy,omitempty"`
	ReviewedAt     string      `json:"reviewedAt,omitempty"`
	ReviewComment  string      `json:"reviewComment,omitempty"`
	StatsRows      []StatsRow  `json:"statsRows,omitempty"`
}

func NormalizeClassification(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, candidate := range SupportedClassifications {
		if value == candidate {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("clasificacion no valida")
}

func NormalizeAgeRange(age int) (string, error) {
	switch {
	case age < 0:
		return "", fmt.Errorf("edad no valida")
	case age <= 17:
		return "0-17", nil
	case age <= 35:
		return "18-35", nil
	case age <= 50:
		return "36-50", nil
	case age <= 65:
		return "51-65", nil
	default:
		return "66+", nil
	}
}

func NormalizeSex(raw string) (string, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	for _, candidate := range SupportedSexValues {
		if value == candidate {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("sexo no valido")
}

func NormalizeOrganizationID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	for _, candidate := range KnownOrganizations {
		if value == candidate {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("organizacion no valida")
}

func IsHospitalOrganization(orgID string) bool {
	orgID = strings.TrimSpace(orgID)
	for _, candidate := range HospitalOrganizations {
		if orgID == candidate {
			return true
		}
	}
	return false
}

func IsResearchCenterOrganization(orgID string) bool {
	orgID = strings.TrimSpace(orgID)
	for _, candidate := range ResearchCenterOrganizations {
		if orgID == candidate {
			return true
		}
	}
	return false
}

func NewLocalRecord(input RecordInput, uploadedBy string, now time.Time) (LocalRecord, error) {
	if strings.TrimSpace(input.PatientUsername) == "" {
		return LocalRecord{}, fmt.Errorf("usuario de paciente no valido")
	}
	if strings.TrimSpace(input.PatientID) == "" {
		return LocalRecord{}, fmt.Errorf("identificador anonimizado de paciente no valido")
	}
	if !IsHospitalOrganization(input.SourceHospital) {
		return LocalRecord{}, fmt.Errorf("hospital de origen no valido")
	}
	classification, err := NormalizeClassification(input.Classification)
	if err != nil {
		return LocalRecord{}, err
	}
	ageRange, err := NormalizeAgeRange(input.Age)
	if err != nil {
		return LocalRecord{}, err
	}
	sex, err := NormalizeSex(input.Sex)
	if err != nil {
		return LocalRecord{}, err
	}

	timestamp := now.UTC().Format(time.RFC3339)
	id := strings.ReplaceAll(now.UTC().Format("20060102T150405.000000000"), ".", "")
	id = fmt.Sprintf("%s-%s", uploadedBy, id)

	return LocalRecord{
		ID:              id,
		Classification:  classification,
		AgeRange:        ageRange,
		Sex:             sex,
		PatientID:       strings.TrimSpace(input.PatientID),
		PatientUsername: strings.TrimSpace(input.PatientUsername),
		PatientAlias:    strings.TrimSpace(input.PatientAlias),
		Observation:     strings.TrimSpace(input.Observation),
		SourceHospital:  strings.TrimSpace(input.SourceHospital),
		CreatedAt:       timestamp,
		UploadedBy:      uploadedBy,
	}, nil
}

func (r LocalRecord) ToAnonymized() AnonymizedRecord {
	return AnonymizedRecord{
		ID:             r.ID,
		Classification: r.Classification,
		AgeRange:       r.AgeRange,
		Sex:            r.Sex,
		PatientID:      r.PatientID,
		SourceHospital: r.SourceHospital,
		CreatedAt:      r.CreatedAt,
		UploadedBy:     r.UploadedBy,
	}
}

func (r AnonymizedRecord) Validate() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.UploadedBy) == "" || strings.TrimSpace(r.PatientID) == "" {
		return fmt.Errorf("faltan identificadores")
	}
	if !IsHospitalOrganization(r.SourceHospital) {
		return fmt.Errorf("hospital de origen no valido")
	}
	if _, err := NormalizeClassification(r.Classification); err != nil {
		return err
	}
	if _, err := NormalizeSex(r.Sex); err != nil {
		return err
	}
	switch r.AgeRange {
	case "0-17", "18-35", "36-50", "51-65", "66+":
		return nil
	default:
		return fmt.Errorf("rango de edad no valido")
	}
}
