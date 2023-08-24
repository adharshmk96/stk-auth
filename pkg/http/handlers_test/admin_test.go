package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetAccountList(t *testing.T) {
	s := gsk.New()

	t.Run("should return 200 if account list is returned", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		accountList := []*ds.Account{
			{
				ID:       ds.AccountID(uuid.New()),
				Username: "test",
			},
		}
		service.On("GetAccountList", mock.AnythingOfType("int"), mock.AnythingOfType("int")).Return(accountList, nil)
		service.On("GetTotalAccountsCount").Return(int64(10), nil).Once()
		// Act
		s.Get("/accountsa", handler.GetAccountList)
		w, err := s.Test(http.MethodGet, "/accountsa?limit=10&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("call service with 0 if limit and offset are not provided", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		accountList := []*ds.Account{
			{
				ID:       ds.AccountID(uuid.New()),
				Username: "test",
			},
		}
		service.On("GetAccountList", 0, 0).Return(accountList, nil)
		service.On("GetTotalAccountsCount").Return(int64(10), nil).Once()
		// Act
		s.Get("/accountsb", handler.GetAccountList)
		w, err := s.Test(http.MethodGet, "/accountsb", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("should call service with provided limit and offset", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		accountList := []*ds.Account{
			{
				ID:       ds.AccountID(uuid.New()),
				Username: "test",
			},
		}
		service.On("GetAccountList", 20, 10).Return(accountList, nil).Once()
		service.On("GetTotalAccountsCount").Return(int64(10), nil).Once()
		// Act
		s.Get("/accountsc", handler.GetAccountList)
		w, err := s.Test(http.MethodGet, "/accountsc?limit=20&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("should return 400 if limit is not a number", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		// Act
		s.Get("/accountsd", handler.GetAccountList)
		w, err := s.Test(http.MethodGet, "/accountsd?limit=a&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("should return 500 if error occurs", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		service.On("GetAccountList", mock.AnythingOfType("int"), mock.AnythingOfType("int")).Return(nil, svrerr.ErrDBStorageFailed).Once()
		// Act
		s.Get("/accountse", handler.GetAccountList)
		w, err := s.Test(http.MethodGet, "/accountse?limit=10&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GetTotalAccountsCount")
	})
}

func TestCreateGroup(t *testing.T) {

	s := gsk.New()

	t.Run("should return 400 if body is invalid", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		// Act
		s.Post("/groups", handler.CreateGroup)

		w, err := s.Test(http.MethodPost, "/groups", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		service.AssertExpectations(t)
	})
	t.Run("should return 201 if group is created", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		group := &ds.Group{
			Name:        "test",
			Description: "test",
		}
		body, _ := json.Marshal(group)

		service.On("CreateGroup", mock.AnythingOfType("*ds.Group")).Return(group, nil)
		// Act
		s.Post("/groups/a", handler.CreateGroup)

		w, err := s.Test(http.MethodPost, "/groups/a", bytes.NewBuffer(body))
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, w.Code)

		service.AssertExpectations(t)
	})
	t.Run("should return 500 if storage fails", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		group := &ds.Group{
			Name:        "test",
			Description: "test",
		}
		body, _ := json.Marshal(group)

		service.On("CreateGroup", mock.AnythingOfType("*ds.Group")).Return(nil, svrerr.ErrDBStorageFailed)
		// Act
		s.Post("/groups/b", handler.CreateGroup)

		w, err := s.Test(http.MethodPost, "/groups/b", bytes.NewBuffer(body))
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		service.AssertExpectations(t)
	})
	t.Run("should return conflict if group is not created", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		group := &ds.Group{
			Name:        "test",
			Description: "test",
		}
		body, _ := json.Marshal(group)

		service.On("CreateGroup", mock.AnythingOfType("*ds.Group")).Return(nil, svrerr.ErrDBDuplicateEntry)
		// Act
		s.Post("/groups/c", handler.CreateGroup)

		w, err := s.Test(http.MethodPost, "/groups/c", bytes.NewBuffer(body))
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, w.Code)

		service.AssertExpectations(t)
	})
}

func TestGetAccountDetail(t *testing.T) {
	storedAccount := &ds.Account{
		ID:        ds.AccountID(uuid.New()),
		Username:  "test",
		Email:     "account@email.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// accountGroups := []*entities.Group{
	// 	{
	// 		ID:          uuid.NewString(),
	// 		Name:        "test",
	// 		Description: "test",
	// 	},
	// 	{
	// 		ID:          uuid.NewString(),
	// 		Name:        "test",
	// 		Description: "test",
	// 	},
	// }

	s := gsk.New()

	t.Run("should return 200 if account is returned", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewAdminHandler(service)
		service.On("GetAccountDetails", storedAccount.ID).Return(storedAccount, nil)
		// service.On("GetGroupsByAccountID", storedAccount.ID).Return(accountGroups, nil)
		// Act
		s.Get("/account", handler.GetAccountDetails)

		w, err := s.Test(http.MethodGet, "/account"+"?id="+storedAccount.ID.String(), nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertExpectations(t)
	})
}
