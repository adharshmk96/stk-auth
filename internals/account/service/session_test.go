package service_test

import (
	"testing"

	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/service"
	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestStartSession(t *testing.T) {
	t.Run("StartSession starts new session", func(t *testing.T) {

		// Arrange
		storage := mocks.NewAccountStorage(t)
		storage.On("StoreSession", mock.AnythingOfType("*domain.Session")).Return(nil)

		svc := service.NewAccountService(storage)

		account := &domain.Account{
			ID: domain.NewAccountID(),
		}

		// Act
		session, err := svc.StartSession(account)

		// Assert
		assert.NoError(t, err)
		assert.NotEmpty(t, session.ID)
		assert.NotEmpty(t, session.CreatedAt)
		assert.Equal(t, session.AccountID, account.ID)
		assert.True(t, session.Active)
	})
}

func TestEndSession(t *testing.T) {
	t.Run("EndSession ends session", func(t *testing.T) {

		// Arrange
		storage := mocks.NewAccountStorage(t)
		storage.On("DeactivateSession", mock.AnythingOfType("string")).Return(nil)

		svc := service.NewAccountService(storage)

		// Act
		err := svc.EndSession("session")

		// Assert
		assert.NoError(t, err)
	})
}
