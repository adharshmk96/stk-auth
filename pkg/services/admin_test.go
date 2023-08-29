package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticationService_GetAccountList(t *testing.T) {
	account_id := ds.AccountID(uuid.New())
	account_name := "testaccount"
	account_email := "account@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &ds.Account{
		ID:        account_id,
		Username:  account_name,
		Email:     account_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns account list defaults 10 if limit is 0", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountList", 10, 0).Return([]*ds.Account{storedData}, nil).Once()

		account, err := service.GetAccountList(0, 0)

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), account[0].ID.String())
		assert.Equal(t, storedData.Username, account[0].Username)
		assert.Equal(t, storedData.Email, account[0].Email)
		assert.Equal(t, storedData.CreatedAt, account[0].CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, account[0].UpdatedAt)
	})

	t.Run("storage error returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountList", 10, 0).Return(nil, svrerr.ErrDBStorageFailed).Once()

		account, err := service.GetAccountList(0, 0)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, account)
	})

	t.Run("returns account list with limit and offset", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountList", 10, 10).Return([]*ds.Account{storedData}, nil).Once()

		account, err := service.GetAccountList(10, 10)

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), account[0].ID.String())
		assert.Equal(t, storedData.Username, account[0].Username)
		assert.Equal(t, storedData.Email, account[0].Email)
		assert.Equal(t, storedData.CreatedAt, account[0].CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, account[0].UpdatedAt)
	})
}

func TestAuthenticationService_GetTotalAccountsCount(t *testing.T) {
	t.Run("returns total account count", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetTotalAccountsCount").Return(int64(10), nil).Once()

		count, err := service.GetTotalAccountsCount()

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, int64(10), count)
	})

	t.Run("storage error returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetTotalAccountsCount").Return(int64(0), svrerr.ErrDBStorageFailed).Once()

		count, err := service.GetTotalAccountsCount()

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Equal(t, int64(0), count)
	})
}

func TestAuthenticationService_GetAccountDetails(t *testing.T) {
	account_id := ds.AccountID(uuid.New())
	account_name := "testaccount"
	account_email := "account@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &ds.Account{
		ID:        account_id,
		Username:  account_name,
		Email:     account_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns account details", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByAccountID", account_id.String()).Return(storedData, nil).Once()

		account, err := service.GetAccountDetails(account_id)

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), account.ID.String())
		assert.Equal(t, storedData.Username, account.Username)
		assert.Equal(t, storedData.Email, account.Email)
		assert.Equal(t, storedData.CreatedAt, account.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, account.UpdatedAt)
	})

	t.Run("storage error returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByAccountID", account_id.String()).Return(nil, svrerr.ErrDBStorageFailed).Once()

		account, err := service.GetAccountDetails(account_id)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, account)
	})
}
