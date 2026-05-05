package client

type Config struct {
	ServerURL        string
	TLSCertPath      string
	LocalDBPath      string
	LocalSaltPath    string
	ProfileKey       string
	ProfileLabel     string
	MasterPassphrase string
}
