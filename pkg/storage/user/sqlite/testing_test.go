package sqlite_test

import (
	"database/sql"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/storage/user/sqlite"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/google/uuid"
)

func setupDatabase() *sql.DB {
	// this singleton pattern has a global effect. So it will make sure storage uses this instance.
	conn := db.GetSqliteConnection(":memory:")

	conn.Exec(`CREATE TABLE auth_user_accounts (
		id TEXT PRIMARY KEY UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		salt TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)

	conn.Exec(`CREATE TABLE auth_user_sessions (
		id integer NOT NULL,
		user_id TEXT NOT NULL,
		session_id varchar(40) NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		valid boolean DEFAULT TRUE,
		PRIMARY KEY (id)
	)`)

	conn.Exec(`CREATE TABLE auth_user_groups (
		id TEXT UNIQUE NOT NULL,
		name VARCHAR(255) UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id)
	);`)

	table := sqlite.TableUserGroupAssociation

	_, err := conn.Exec(`CREATE TABLE ` + table + ` (
		id INTEGER AUTO INCREMENT,
		user_id TEXT NOT NULL,
		group_id TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (user_id, group_id),
		FOREIGN KEY(user_id) REFERENCES  auth_user_accounts(id),
		FOREIGN KEY(group_id) REFERENCES  auth_user_groups(id)
	);`)

	if err != nil {
		panic(err)
	}

	return conn
}

func tearDownDatabase() {
	conn := db.GetSqliteConnection(":memory:")
	conn.Exec("DROP TABLE auth_user_accounts")
	conn.Exec("DROP TABLE auth_user_sessions")
	conn.Close()
	db.ResetSqliteConnection()
}

func generateRandomUser() *entities.User {
	userId := entities.UserID(uuid.New())
	username := "test" + uuid.NewString()
	email := "u" + uuid.NewString() + "@mail.com"
	password := "Test123#"
	salt := "test" + uuid.NewString()
	time_now := time.Now()

	user := &entities.User{
		ID:        userId,
		Username:  username,
		Password:  password,
		Salt:      salt,
		Email:     email,
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	return user
}
