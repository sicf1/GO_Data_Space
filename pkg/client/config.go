package client

type Config struct {
	ServerURL        string
	TLSCertPath      string
	LocalDBPath      string
	LocalSaltPath    string
	MasterPassphrase string
}
