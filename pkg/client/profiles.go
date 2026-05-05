package client

import "path/filepath"

type Profile struct {
	Key   string
	Label string
}

func AvailableProfiles() []Profile {
	return []Profile{
		{Key: "hospital1", Label: "hospital1"},
		{Key: "hospital2", Label: "hospital2"},
		{Key: "hospital3", Label: "hospital3"},
		{Key: "centro_investigacion1", Label: "centro de investigacion1"},
	}
}

func BuildProfileConfig(profile Profile, masterPassphrase string) Config {
	baseDir := filepath.Join("data", "clients", profile.Key)
	return Config{
		ServerURL:        "https://localhost:8443/api",
		TLSCertPath:      filepath.Join("data", "server", "tls", "server.crt"),
		LocalDBPath:      filepath.Join(baseDir, "client.db"),
		LocalSaltPath:    filepath.Join(baseDir, "client.salt"),
		ProfileKey:       profile.Key,
		ProfileLabel:     profile.Label,
		MasterPassphrase: masterPassphrase,
	}
}
