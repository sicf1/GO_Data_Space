package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"sprout/pkg/api"
	"sprout/pkg/store"

	"golang.org/x/term"
)

type config struct {
	target   string
	profile  string
	dbPath   string
	saltPath string
	master   string
}

func main() {
	cfg := parseFlags()

	db, err := openSecureDB(cfg.dbPath, cfg.saltPath, cfg.master)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error abriendo la base de datos: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	switch cfg.target {
	case "server":
		inspectServer(db)
	case "client":
		inspectClient(db)
	default:
		fmt.Fprintf(os.Stderr, "target no valido: %s\n", cfg.target)
		os.Exit(1)
	}
}

func parseFlags() config {
	target := flag.String("target", "server", "base de datos a inspeccionar: server o client")
	profile := flag.String("profile", "hospital1", "perfil de cliente a inspeccionar cuando target=client")
	dbPath := flag.String("db", "", "ruta a la base de datos")
	saltPath := flag.String("salt", "", "ruta al fichero de sal")
	master := flag.String("master", "", "contrasena maestra; si se omite, se pedira por terminal")
	flag.Parse()

	cfg := config{
		target:   *target,
		profile:  *profile,
		dbPath:   *dbPath,
		saltPath: *saltPath,
		master:   *master,
	}

	switch cfg.target {
	case "server":
		if cfg.dbPath == "" {
			cfg.dbPath = filepath.Join("data", "server", "server.db")
		}
		if cfg.saltPath == "" {
			cfg.saltPath = filepath.Join("data", "server", "master.salt")
		}
	case "client":
		if cfg.dbPath == "" {
			cfg.dbPath = filepath.Join("data", "clients", cfg.profile, "client.db")
		}
		if cfg.saltPath == "" {
			cfg.saltPath = filepath.Join("data", "clients", cfg.profile, "client.salt")
		}
	default:
		fmt.Fprintf(os.Stderr, "target no valido: %s\n", cfg.target)
		os.Exit(1)
	}

	if cfg.master == "" {
		fmt.Print("Contrasena maestra: ")
		raw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "no se pudo leer la contrasena maestra: %v\n", err)
			os.Exit(1)
		}
		cfg.master = string(raw)
	}

	return cfg
}

func openSecureDB(dbPath, saltPath, master string) (store.Store, error) {
	base, err := store.NewStore("bbolt", dbPath)
	if err != nil {
		return nil, err
	}

	salt, err := os.ReadFile(saltPath)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	if len(salt) < 16 {
		_ = base.Close()
		return nil, fmt.Errorf("sal invalida en %s", saltPath)
	}

	key := store.DeriveKey(master, salt)
	secure, err := store.NewSecureStore(base, key)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	if err := secure.VerifyOrInit(); err != nil {
		_ = secure.Close()
		return nil, err
	}
	return secure, nil
}

func inspectServer(db store.Store) {
	fmt.Println("== SERVER DB ==")
	printJSONNamespace(db, "users")
	printJSONNamespace(db, "patient_ids")
	printJSONNamespace(db, "sessions")
	printJSONNamespace(db, "records")
	printJSONNamespace(db, "queries")
}

func inspectClient(db store.Store) {
	fmt.Println("== CLIENT DB ==")
	printXMLNamespace(db, "local_records")
}

func printJSONNamespace(db store.Store, namespace string) {
	keys, err := db.ListKeys(namespace)
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			fmt.Printf("\n[%s]\n(vacio)\n", namespace)
			return
		}
		fmt.Printf("\n[%s]\nerror listando claves: %v\n", namespace, err)
		return
	}

	sort.Slice(keys, func(i, j int) bool {
		return string(keys[i]) < string(keys[j])
	})

	fmt.Printf("\n[%s]\n", namespace)
	if len(keys) == 0 {
		fmt.Println("(vacio)")
		return
	}

	for _, key := range keys {
		value, err := db.Get(namespace, key)
		if err != nil {
			fmt.Printf("- key=%s | error leyendo valor: %v\n", string(key), err)
			continue
		}

		var payload any
		if err := json.Unmarshal(value, &payload); err != nil {
			fmt.Printf("- key=%s | json invalido: %v\n", string(key), err)
			continue
		}

		pretty, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fmt.Printf("- key=%s | error formateando json: %v\n", string(key), err)
			continue
		}

		fmt.Printf("- key=%s\n%s\n", string(key), string(pretty))
	}
}

func printXMLNamespace(db store.Store, namespace string) {
	keys, err := db.ListKeys(namespace)
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			fmt.Printf("\n[%s]\n(vacio)\n", namespace)
			return
		}
		fmt.Printf("\n[%s]\nerror listando claves: %v\n", namespace, err)
		return
	}

	sort.Slice(keys, func(i, j int) bool {
		return string(keys[i]) < string(keys[j])
	})

	fmt.Printf("\n[%s]\n", namespace)
	if len(keys) == 0 {
		fmt.Println("(vacio)")
		return
	}

	for _, key := range keys {
		value, err := db.Get(namespace, key)
		if err != nil {
			fmt.Printf("- key=%s | error leyendo valor: %v\n", string(key), err)
			continue
		}

		var record api.LocalRecord
		if err := xml.Unmarshal(value, &record); err != nil {
			fmt.Printf("- key=%s | xml invalido: %v\n", string(key), err)
			continue
		}

		pretty, err := xml.MarshalIndent(record, "", "  ")
		if err != nil {
			fmt.Printf("- key=%s | error formateando xml: %v\n", string(key), err)
			continue
		}

		fmt.Printf("- key=%s\n%s\n", string(key), string(pretty))
	}
}
