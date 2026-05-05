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
		c.DBPath = "data/server/server.db"
	}
	if c.SaltPath == "" {
		c.SaltPath = "data/server/master.salt"
	}
	if c.TLSCertPath == "" {
		c.TLSCertPath = "data/server/tls/server.crt"
	}
	if c.TLSKeyPath == "" {
		c.TLSKeyPath = "data/server/tls/server.key"
	}
	if c.SessionIdleTimeout == 0 {
		c.SessionIdleTimeout = 30 * time.Minute
	}
	return c
}
