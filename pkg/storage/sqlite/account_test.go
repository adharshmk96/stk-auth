package sqlite_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/storage/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/db"
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
		user_id TEXT NOT NULL,
		session_id varchar(40) NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		valid boolean DEFAULT TRUE,
		PRIMARY KEY (id)
	)`)

	conn.Exec(
		sqlite.ACCOUNT_INSERT_USER_QUERY,
		"invalid",
		"invalid",
		"invalid",
		"invalid",
		"invalid",
		time.Now(),
		time.Now(),
	)

	return conn
}

func tearDownDatabase() {
	conn := db.GetSqliteConnection(":memory:")
	conn.Exec("DROP TABLE auth_user_accounts")
	conn.Exec("DROP TABLE auth_user_sessions")
	conn.Close()
	db.ResetSqliteConnection()
}

func TestUserStorage_EmptyDatabase(t *testing.T) {

	conn := setupDatabase()
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

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetUserByEmail returns error when email is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail(user.Email)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUsername returns error when username is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername(user.Username)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUserID returns error when username is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUserID(user.Username)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByEmail get user by email returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUsername get user by username returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUserID get user by username returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUserID("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("SaveUser saves user to database without error", func(t *testing.T) {
		err := userStorage.SaveUser(user)
		assert.NoError(t, err)
	})

	t.Run("SaveUser returns error when same user is saved again", func(t *testing.T) {
		user := &entities.Account{
			ID:        entities.UserID(uuid.New()),
			Username:  "test2",
			Password:  "test",
			Salt:      "salt",
			Email:     "user2@test.com",
			CreatedAt: time_now,
			UpdatedAt: time_now,
		}
		err := userStorage.SaveUser(user)
		assert.NoError(t, err)
		err = userStorage.SaveUser(user)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})

}

func TestUserStorage_GetUserByX(t *testing.T) {

	conn := setupDatabase()
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

	_, err := conn.Exec(
		sqlite.ACCOUNT_INSERT_USER_QUERY,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)

	assert.NoError(t, err)
	t.Log("User inserted successfully")

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetUserByEmail retrieves user by email", func(t *testing.T) {
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

	t.Run("GetUserByUsername retrieves user by username", func(t *testing.T) {
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

	t.Run("GetUserByUserID retrieves user by id", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserByUserID(userId.String())
		assert.NoError(t, err)
		assert.Equal(t, userId, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("GetUserByEmail returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail(user.Email + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUsername returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername(user.Username + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUserID returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUserID(uuid.New().String())
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})
}

func TestUserStorage_GetSessionByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	userId := entities.UserID(uuid.New())
	sessionId := uuid.NewString()
	time_now := time.Now()

	session := &entities.Session{
		UserID:    userId,
		SessionID: sessionId,
		CreatedAt: time_now,
		UpdatedAt: time_now,
		Valid:     true,
	}

	conn.Exec(
		sqlite.ACCOUNT_INSERT_SESSION_QUERY,
		session.UserID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetSessionByID returns error when session is not found in empty db", func(t *testing.T) {
		presaveSession, err := userStorage.GetSessionByID("test")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveSession)
	})

	t.Run("GetSessionByID returns error when parsing invalid user id", func(t *testing.T) {
		presaveUser, err := userStorage.GetSessionByID("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("SaveSession saves user session to database", func(t *testing.T) {
		session := &entities.Session{
			UserID:    userId,
			SessionID: sessionId + "sd",
			CreatedAt: time_now,
			UpdatedAt: time_now,
			Valid:     true,
		}
		err := userStorage.SaveSession(session)
		assert.NoError(t, err)
	})

	t.Run("SaveSession returns error when same session is saved again", func(t *testing.T) {
		session := &entities.Session{
			UserID:    userId,
			SessionID: sessionId + "xd2",
			CreatedAt: time_now,
			UpdatedAt: time_now,
			Valid:     true,
		}
		err := userStorage.SaveSession(session)
		assert.NoError(t, err)
		err = userStorage.SaveSession(session)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})

	t.Run("GetSessionByID retrieves valid session succesfully", func(t *testing.T) {
		session, err := userStorage.GetSessionByID(sessionId)
		assert.NoError(t, err)
		assert.Equal(t, userId, session.UserID)
		assert.Equal(t, sessionId, session.SessionID)
		assert.Equal(t, time_now.Unix(), session.CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), session.UpdatedAt.Unix())
		assert.Equal(t, true, session.Valid)
	})

}

func TestUserStorage_GetUserBySessionID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	userId := entities.UserID(uuid.New())
	username := "test"
	email := "test@user.com"
	password := "test"
	salt := "test"
	time_now := time.Now()
	sessionId := uuid.NewString()

	user := &entities.Account{
		ID:        userId,
		Username:  username,
		Password:  password,
		Salt:      salt,
		Email:     email,
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	session := &entities.Session{
		UserID:    userId,
		SessionID: sessionId,
		CreatedAt: time_now,
		UpdatedAt: time_now,
		Valid:     true,
	}

	conn.Exec(
		sqlite.ACCOUNT_INSERT_USER_QUERY,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)
	conn.Exec(
		sqlite.ACCOUNT_INSERT_SESSION_QUERY,
		session.UserID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetUserBySessionID retrieves user by session id", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserBySessionID(sessionId)
		assert.NoError(t, err)
		assert.Equal(t, userId.String(), retrievedUser.ID.String())
		assert.Equal(t, username, retrievedUser.Username)
		assert.Equal(t, email, retrievedUser.Email)
		assert.Equal(t, time_now.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("GetUserBySessionID returns error when session id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserBySessionID("session" + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

}

func TestUserStorage_InvalidateSessionByID(t *testing.T) {

}
