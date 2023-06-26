package sqlite_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/storage/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
		user_id TEXT UNIQUE,
		session_id varchar(40) NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		valid boolean DEFAULT TRUE,
		PRIMARY KEY (id)
	)`)

	conn.Exec(`insert into auth_user_accounts (id, username, password, salt, email ) values ('invalid', 'invalid', 'test', 'salt', 'invalid' `)
	conn.Exec(`insert into auth_user_sessions (id, user_id, session_id) values (1, 'invalid', 'invalid')`)

	return conn
}

func tearDownDatabase() {
	conn := db.GetSqliteConnection(":memory:")
	conn.Close()
}

func TestSaveAndRetrieveUser(t *testing.T) {

	setupDatabase()
	defer tearDownDatabase()

	userId := entities.UserID(uuid.New())
	time_now := time.Now()

	user := &entities.Account{
		ID:        userId,
		Username:  "test",
		Password:  "test",
		Salt:      "salt",
		Email:     "user@test.com",
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	userStorage := sqlite.NewAccountStorage()

	t.Run("returns error when email is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail(user.Email)
		assert.EqualError(t, err, svrerr.ErrEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("returns error when username is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername(user.Username)
		assert.EqualError(t, err, svrerr.ErrEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("saves user to database", func(t *testing.T) {
		err := userStorage.SaveUser(user)
		assert.NoError(t, err)
	})

	t.Run("returns error when same user is saved again", func(t *testing.T) {
		err := userStorage.SaveUser(user)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDuplicateEntry.Error())
	})

	t.Run("retrieves user by email", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserByEmail(user.Email)
		assert.NoError(t, err)
		assert.Equal(t, userId, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("retrieves user by username", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserByUsername(user.Username)
		assert.NoError(t, err)
		assert.Equal(t, userId, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail(user.Email + "xd")
		assert.EqualError(t, err, svrerr.ErrEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	session := &entities.Session{
		UserID:    userId,
		SessionID: "session",
		CreatedAt: time_now,
		UpdatedAt: time_now,
		Valid:     true,
	}

	t.Run("returns error when session is not found in empty db", func(t *testing.T) {
		presaveSession, err := userStorage.GetSessionByID("test")
		assert.EqualError(t, err, svrerr.ErrEntryNotFound.Error())
		assert.Nil(t, presaveSession)
	})

	t.Run("returns error when parsing invalid user id", func(t *testing.T) {
		presaveUser, err := userStorage.GetSessionByID("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("saves user session to database", func(t *testing.T) {
		err := userStorage.SaveSession(session)
		assert.NoError(t, err)
	})

	t.Run("returns error when same session is saved again", func(t *testing.T) {
		err := userStorage.SaveSession(session)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDuplicateEntry.Error())
	})

	t.Run("retrieves user session by session id", func(t *testing.T) {
		session, err := userStorage.GetSessionByID("session")
		assert.NoError(t, err)
		assert.Equal(t, userId, session.UserID)
		assert.Equal(t, "session", session.SessionID)
		assert.Equal(t, time_now.Unix(), session.CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), session.UpdatedAt.Unix())
		assert.Equal(t, true, session.Valid)
	})

}
