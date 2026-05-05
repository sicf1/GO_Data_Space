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

type QueryStatus string

const (
	QueryPending  QueryStatus = "pending"
	QueryApproved QueryStatus = "approved"
	QueryDenied   QueryStatus = "denied"
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
	CreatedAt       string   `xml:"createdAt" json:"createdAt"`
	UploadedBy      string   `xml:"uploadedBy" json:"uploadedBy"`
}

type AnonymizedRecord struct {
	ID             string `json:"id"`
	Classification string `json:"classification"`
	AgeRange       string `json:"ageRange"`
	Sex            string `json:"sex"`
	PatientID      string `json:"patientId"`
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

type StatsRequest struct {
	ID             string      `json:"id"`
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

func NewLocalRecord(input RecordInput, uploadedBy string, now time.Time) (LocalRecord, error) {
	if strings.TrimSpace(input.PatientUsername) == "" {
		return LocalRecord{}, fmt.Errorf("usuario de paciente no valido")
	}
	if strings.TrimSpace(input.PatientID) == "" {
		return LocalRecord{}, fmt.Errorf("identificador anonimizado de paciente no valido")
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
		CreatedAt:      r.CreatedAt,
		UploadedBy:     r.UploadedBy,
	}
}

func (r AnonymizedRecord) Validate() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.UploadedBy) == "" || strings.TrimSpace(r.PatientID) == "" {
		return fmt.Errorf("faltan identificadores")
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
