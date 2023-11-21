package storage_test

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func GetTestConnection(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	initializeDB(t, db)

	return db
}

func initializeDB(t *testing.T, conn *sql.DB) {
	t.Helper()
	_, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS account (
			id TEXT PRIMARY KEY,
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			password TEXT NOT NULL,
			salt TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS session (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			active BOOLEAN NOT NULL,
			created_at TIMESTAMP NOT NULL
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

}
