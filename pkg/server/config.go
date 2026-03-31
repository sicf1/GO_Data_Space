package server

import "time"

type Config struct {
	Addr               string
	DBPath             string
	SaltPath           string
	TLSCertPath        string
	TLSKeyPath         string
	MasterPassphrase   string
	SessionIdleTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.Addr == "" {
		c.Addr = ":8443"
	}
	if c.DBPath == "" {
		c.DBPath = "data/server.db"
	}
	if c.SaltPath == "" {
		c.SaltPath = "data/master.salt"
	}
	if c.TLSCertPath == "" {
		c.TLSCertPath = "data/tls/server.crt"
	}
	if c.TLSKeyPath == "" {
		c.TLSKeyPath = "data/tls/server.key"
	}
	if c.SessionIdleTimeout == 0 {
		c.SessionIdleTimeout = 30 * time.Minute
	}
	return c
}
