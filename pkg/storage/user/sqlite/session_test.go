package sqlite_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/storage/user/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

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
		sqlite.Q_InsertSession,
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

	user := &entities.User{
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
		sqlite.Q_InsertUserQuery,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)
	conn.Exec(
		sqlite.Q_InsertSession,
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

func TestInvalidateSessionByID(t *testing.T) {
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
		sqlite.Q_InsertSession,
		session.UserID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("InvalidateSessionByID invalidates session by id", func(t *testing.T) {
		err := userStorage.InvalidateSessionByID(sessionId)
		assert.NoError(t, err)

		retrievedSession, err := userStorage.GetSessionByID(sessionId)
		assert.Error(t, err)
		assert.Nil(t, retrievedSession)
	})

	t.Run("InvalidateSessionByID returns error when session id is not found in populated db", func(t *testing.T) {
		err := userStorage.InvalidateSessionByID("session" + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

}
