package service_test

import (
	"testing"

	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/service"
	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateAccount(t *testing.T) {
	t.Run("CreateAccount creates new account", func(t *testing.T) {

		// Arrange
		storage := mocks.NewAccountStorage(t)
		storage.On("StoreAccount", mock.AnythingOfType("*domain.Account")).Return(nil)

		svc := service.NewAccountService(storage)

		password := "password"

		newAccount := &domain.Account{
			Email:    "user@email.com",
			Password: password,
		}

		// Act
		err := svc.CreateAccount(newAccount)

		// Assert
		assert.NoError(t, err)

		assert.NotEmpty(t, newAccount.Salt)
		assert.NotEqual(t, newAccount.Password, password)
		assert.NotEmpty(t, newAccount.ID)
		assert.NotEmpty(t, newAccount.CreatedAt)
		assert.NotEmpty(t, newAccount.UpdatedAt)
	})
}
