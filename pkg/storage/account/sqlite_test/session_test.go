package sqlite_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/storage/account/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAccountStorage_GetSessionByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountId := ds.AccountID(uuid.New())
	sessionId := uuid.NewString()
	time_now := time.Now()

	session := &ds.Session{
		AccountID: accountId,
		SessionID: sessionId,
		CreatedAt: time_now,
		UpdatedAt: time_now,
		Valid:     true,
	}

	conn.Exec(
		sqlite.Q_InsertSession,
		session.AccountID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetSessionByID returns error when session is not found in empty db", func(t *testing.T) {
		presaveSession, err := accountStorage.GetSessionByID("test")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveSession)
	})

	t.Run("GetSessionByID returns error when parsing invalid account id", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetSessionByID("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveAccount)
	})

	t.Run("SaveSession saves account session to database", func(t *testing.T) {
		session := &ds.Session{
			AccountID: accountId,
			SessionID: sessionId + "sd",
			CreatedAt: time_now,
			UpdatedAt: time_now,
			Valid:     true,
		}
		err := accountStorage.SaveSession(session)
		assert.NoError(t, err)
	})

	t.Run("SaveSession returns error when same session is saved again", func(t *testing.T) {
		session := &ds.Session{
			AccountID: accountId,
			SessionID: sessionId + "xd2",
			CreatedAt: time_now,
			UpdatedAt: time_now,
			Valid:     true,
		}
		err := accountStorage.SaveSession(session)
		assert.NoError(t, err)
		err = accountStorage.SaveSession(session)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})

	t.Run("GetSessionByID retrieves valid session succesfully", func(t *testing.T) {
		session, err := accountStorage.GetSessionByID(sessionId)
		assert.NoError(t, err)
		assert.Equal(t, accountId, session.AccountID)
		assert.Equal(t, sessionId, session.SessionID)
		assert.Equal(t, time_now.Unix(), session.CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), session.UpdatedAt.Unix())
		assert.Equal(t, true, session.Valid)
	})

}

func TestAccountStorage_GetAccountBySessionID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountId := ds.AccountID(uuid.New())
	username := "test"
	email := "test@account.com"
	password := "test"
	salt := "test"
	time_now := time.Now()
	sessionId := uuid.NewString()

	account := &ds.Account{
		ID:        accountId,
		Username:  username,
		Password:  password,
		Salt:      salt,
		Email:     email,
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	session := &ds.Session{
		AccountID: accountId,
		SessionID: sessionId,
		CreatedAt: time_now,
		UpdatedAt: time_now,
		Valid:     true,
	}

	conn.Exec(
		sqlite.Q_InsertAccountQuery,
		account.ID.String(),
		account.Username,
		account.Password,
		account.Salt,
		account.Email,
		account.CreatedAt,
		account.UpdatedAt,
	)
	conn.Exec(
		sqlite.Q_InsertSession,
		session.AccountID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetAccountBySessionID retrieves account by session id", func(t *testing.T) {
		retrievedAccount, err := accountStorage.GetAccountBySessionID(sessionId)
		assert.NoError(t, err)
		assert.Equal(t, accountId.String(), retrievedAccount.ID.String())
		assert.Equal(t, username, retrievedAccount.Username)
		assert.Equal(t, email, retrievedAccount.Email)
		assert.Equal(t, time_now.Unix(), retrievedAccount.CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), retrievedAccount.UpdatedAt.Unix())
	})

	t.Run("GetAccountBySessionID returns error when session id is not found in populated db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountBySessionID("session" + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})

}

func TestAccountStorage_InvalidateSessionByID(t *testing.T) {

}

func TestInvalidateSessionByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountId := ds.AccountID(uuid.New())
	sessionId := uuid.NewString()
	time_now := time.Now()

	session := &ds.Session{
		AccountID: accountId,
		SessionID: sessionId,
		CreatedAt: time_now,
		UpdatedAt: time_now,
		Valid:     true,
	}

	conn.Exec(
		sqlite.Q_InsertSession,
		session.AccountID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("InvalidateSessionByID invalidates session by id", func(t *testing.T) {
		err := accountStorage.InvalidateSessionByID(sessionId)
		assert.NoError(t, err)

		retrievedSession, err := accountStorage.GetSessionByID(sessionId)
		assert.Error(t, err)
		assert.Nil(t, retrievedSession)
	})

	t.Run("InvalidateSessionByID returns error when session id is not found in populated db", func(t *testing.T) {
		err := accountStorage.InvalidateSessionByID("session" + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

}
