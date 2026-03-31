package client

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sprout/pkg/api"
	"sprout/pkg/store"
)

const localRecordsNamespace = "local_records"

func openLocalStore(cfg Config) (store.Store, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.LocalDBPath), 0755); err != nil {
		return nil, fmt.Errorf("no se ha podido crear la carpeta local: %w", err)
	}
	base, err := store.NewStore("bbolt", cfg.LocalDBPath)
	if err != nil {
		return nil, err
	}
	salt, err := store.LoadOrCreateSalt(cfg.LocalSaltPath)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	key := store.DeriveKey(cfg.MasterPassphrase, salt)
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

func localRecordKey(doctorUsername, recordID string) string {
	return doctorUsername + "/" + recordID
}

func localRecordPrefix(doctorUsername string) []byte {
	return []byte(doctorUsername + "/")
}

func storeLocalRecord(db store.Store, record api.LocalRecord) error {
	raw, err := xml.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return db.Put(localRecordsNamespace, []byte(localRecordKey(record.UploadedBy, record.ID)), raw)
}

func loadLocalRecord(db store.Store, key []byte) (api.LocalRecord, error) {
	raw, err := db.Get(localRecordsNamespace, key)
	if err != nil {
		return api.LocalRecord{}, err
	}
	var record api.LocalRecord
	if err := xml.Unmarshal(raw, &record); err != nil {
		return api.LocalRecord{}, err
	}
	return record, nil
}

func listLocalRecords(db store.Store, doctorUsername string) ([]api.LocalRecord, error) {
	keys, err := db.KeysByPrefix(localRecordsNamespace, localRecordPrefix(doctorUsername))
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	records := make([]api.LocalRecord, 0, len(keys))
	for _, key := range keys {
		record, err := loadLocalRecord(db, key)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func shortClassificationOptions() string {
	return strings.Join(api.SupportedClassifications, ", ")
}
