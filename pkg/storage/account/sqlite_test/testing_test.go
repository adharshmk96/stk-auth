package sqlite_test

import (
	"database/sql"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/storage/account/sqlite"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/google/uuid"
)

func setupDatabase() *sql.DB {
	// this singleton pattern has a global effect. So it will make sure storage uses this instance.
	conn := db.GetSqliteConnection(":memory:")

	conn.Exec(`CREATE TABLE ` + sqlite.TableAccount + ` (
		id TEXT PRIMARY KEY UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		salt TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)

	conn.Exec(`CREATE TABLE ` + sqlite.TableSession + ` (
		id integer NOT NULL,
		account_id TEXT NOT NULL,
		session_id varchar(40) NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		valid boolean DEFAULT TRUE,
		PRIMARY KEY (id)
	)`)

	conn.Exec(`CREATE TABLE ` + sqlite.TableGroup + ` (
		id TEXT UNIQUE NOT NULL,
		name VARCHAR(255) UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id)
	);`)

	_, err := conn.Exec(`CREATE TABLE ` + sqlite.TableAccountGroupAssociation + ` (
		id INTEGER AUTO INCREMENT,
		account_id TEXT NOT NULL,
		group_id TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (account_id, group_id),
		FOREIGN KEY(account_id) REFERENCES  auth_account_accounts(id),
		FOREIGN KEY(group_id) REFERENCES  auth_account_groups(id)
	);`)

	if err != nil {
		panic(err)
	}

	return conn
}

func tearDownDatabase() {
	conn := db.GetSqliteConnection(":memory:")
	conn.Exec("DROP TABLE auth_account_accounts")
	conn.Exec("DROP TABLE auth_account_sessions")
	conn.Close()
	db.ResetSqliteConnection()
}

func generateRandomAccount() *ds.Account {
	accountId := ds.AccountID(uuid.New())
	username := "test" + uuid.NewString()
	email := "u" + uuid.NewString() + "@mail.com"
	password := "Test123#"
	salt := "test" + uuid.NewString()
	time_now := time.Now()

	account := &ds.Account{
		ID:        accountId,
		Username:  username,
		Password:  password,
		Salt:      salt,
		Email:     email,
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	return account
}
