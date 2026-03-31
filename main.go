/*
'sprout' es una base para el desarrollo de prácticas en clase con Go.

Se puede compilar con "go build" en el directorio donde resida main.go
o "go build -o nombre" para que el ejecutable tenga un nombre distinto.
*/
package main

import (
	"log"
	"os"
	"time"

	"sprout/pkg/client"
	"sprout/pkg/server"
	"sprout/pkg/ui"
)

func main() {
	mainLog := log.New(os.Stdout, "[main] ", log.LstdFlags)

	if err := os.MkdirAll("data", 0755); err != nil {
		mainLog.Fatalf("No se ha podido crear la carpeta de datos: %v", err)
	}

	masterPassphrase, err := ui.ReadPassword("Contraseña maestra de cifrado")
	if err != nil || masterPassphrase == "" {
		mainLog.Fatalf("No se ha podido leer la contraseña maestra")
	}

	serverCfg := server.Config{
		Addr:               ":8443",
		DBPath:             "data/server.db",
		SaltPath:           "data/master.salt",
		TLSCertPath:        "data/tls/server.crt",
		TLSKeyPath:         "data/tls/server.key",
		MasterPassphrase:   masterPassphrase,
		SessionIdleTimeout: 30 * time.Minute,
	}
	clientCfg := client.Config{
		ServerURL:        "https://localhost:8443/api",
		TLSCertPath:      "data/tls/server.crt",
		LocalDBPath:      "data/client.db",
		LocalSaltPath:    "data/client.salt",
		MasterPassphrase: masterPassphrase,
	}

	needsAdmin, err := server.NeedsInitialAdmin(serverCfg)
	if err != nil {
		mainLog.Fatalf("No se ha podido verificar el administrador inicial: %v", err)
	}
	if needsAdmin {
		mainLog.Println("No existe administrador inicial; se va a crear ahora.")
		adminUser := ui.ReadInput("Usuario administrador inicial")
		adminPassword, err := ui.ReadPassword("Contraseña del administrador inicial")
		if err != nil || adminPassword == "" {
			mainLog.Fatalf("No se ha podido leer la contraseña del administrador inicial")
		}
		if err := server.BootstrapInitialAdmin(serverCfg, adminUser, adminPassword); err != nil {
			mainLog.Fatalf("No se ha podido crear el administrador inicial: %v", err)
		}
	}

	mainLog.Println("Iniciando servidor...")
	go func() {
		if err := server.Run(serverCfg); err != nil {
			mainLog.Fatalf("Error del servidor: %v", err)
		}
	}()

	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	mainLog.Println("Iniciando cliente...")
	if err := client.Run(clientCfg); err != nil {
		mainLog.Fatalf("Error del cliente: %v", err)
	}
}
