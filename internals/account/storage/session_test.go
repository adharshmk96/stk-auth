package storage_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/storage"
	"github.com/stretchr/testify/assert"
)

func TestStoreSession(t *testing.T) {

	dbConn := GetTestConnection(t)

	t.Run("StoreSession stores session", func(t *testing.T) {

		// Arrange
		storage := storage.NewSqliteRepo(dbConn)

		session := &domain.Session{
			ID:        domain.NewSessionID(),
			AccountID: domain.NewAccountID(),
			Active:    true,
			CreatedAt: time.Now(),
		}

		// Act
		err := storage.StoreSession(session)

		// Assert
		assert.NoError(t, err)

		// Assert that the session is stored in the database
		var storedSession domain.Session
		var accountId string
		err = dbConn.QueryRow("SELECT id, account_id, active, created_at FROM session WHERE id = ?", session.ID).Scan(
			&storedSession.ID,
			&accountId,
			&storedSession.Active,
			&storedSession.CreatedAt,
		)

		assert.NoError(t, err)
	})
}
