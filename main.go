/*
Sprout es una base para el desarrollo de practicas en clase con Go.

Se puede compilar con "go build" en el directorio donde resida main.go
o "go build -o nombre" para que el ejecutable tenga un nombre distinto.
*/
package main

import (
	"log"
	"os"
	"path/filepath"
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

	profiles := client.AvailableProfiles()
	options := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		options = append(options, profile.Label)
	}
	selectedProfile := profiles[ui.PrintMenu("Selecciona la entidad cliente", options)-1]

	clientMasterPassphrase, err := ui.ReadPassword("Clave maestra de " + selectedProfile.Label)
	if err != nil || clientMasterPassphrase == "" {
		mainLog.Fatalf("No se ha podido leer la clave maestra de %s", selectedProfile.Label)
	}

	serverMasterPassphrase, err := ui.ReadPassword("Clave maestra del servidor compartido")
	if err != nil || serverMasterPassphrase == "" {
		mainLog.Fatalf("No se ha podido leer la clave maestra del servidor")
	}

	serverCfg := server.Config{
		Addr:               ":8443",
		DBPath:             filepath.Join("data", "server", "server.db"),
		SaltPath:           filepath.Join("data", "server", "master.salt"),
		TLSCertPath:        filepath.Join("data", "server", "tls", "server.crt"),
		TLSKeyPath:         filepath.Join("data", "server", "tls", "server.key"),
		MasterPassphrase:   serverMasterPassphrase,
		SessionIdleTimeout: 30 * time.Minute,
	}
	clientCfg := client.BuildProfileConfig(selectedProfile, clientMasterPassphrase)

	needsAdmin, err := server.NeedsInitialAdmin(serverCfg)
	if err != nil {
		mainLog.Fatalf("No se ha podido verificar el administrador inicial: %v", err)
	}
	if needsAdmin {
		mainLog.Println("No existe administrador inicial; se va a crear ahora.")
		adminUser := ui.ReadInput("Usuario administrador inicial")
		adminPassword, err := ui.ReadPassword("Contrasena del administrador inicial")
		if err != nil || adminPassword == "" {
			mainLog.Fatalf("No se ha podido leer la contrasena del administrador inicial")
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

	mainLog.Printf("Iniciando %s...\n", selectedProfile.Label)
	if err := client.Run(clientCfg); err != nil {
		mainLog.Fatalf("Error de %s: %v", selectedProfile.Label, err)
	}
}
