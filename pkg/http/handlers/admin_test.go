package handlers_test

import (
	"net/http"
	"testing"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetUserList(t *testing.T) {
	s := gsk.New()

	t.Run("should return 200 if user list is returned", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)
		userList := []*entities.User{
			{
				ID:       entities.UserID(uuid.New()),
				Username: "test",
			},
		}
		service.On("GetUserList", mock.AnythingOfType("int"), mock.AnythingOfType("int")).Return(userList, nil)
		service.On("GetTotalUsersCount").Return(int64(10), nil).Once()
		// Act
		s.Get("/usersa", handler.GetUserList)
		w, err := s.Test(http.MethodGet, "/usersa?limit=10&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("call service with 0 if limit and offset are not provided", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)
		userList := []*entities.User{
			{
				ID:       entities.UserID(uuid.New()),
				Username: "test",
			},
		}
		service.On("GetUserList", 0, 0).Return(userList, nil)
		service.On("GetTotalUsersCount").Return(int64(10), nil).Once()
		// Act
		s.Get("/usersb", handler.GetUserList)
		w, err := s.Test(http.MethodGet, "/usersb", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("should call service with provided limit and offset", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)
		userList := []*entities.User{
			{
				ID:       entities.UserID(uuid.New()),
				Username: "test",
			},
		}
		service.On("GetUserList", 20, 10).Return(userList, nil).Once()
		service.On("GetTotalUsersCount").Return(int64(10), nil).Once()
		// Act
		s.Get("/usersc", handler.GetUserList)
		w, err := s.Test(http.MethodGet, "/usersc?limit=20&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("should return 400 if limit is not a number", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)
		// Act
		s.Get("/usersd", handler.GetUserList)
		w, err := s.Test(http.MethodGet, "/usersd?limit=a&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("should return 500 if error occurs", func(t *testing.T) {
		// Arrange
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)
		service.On("GetUserList", mock.AnythingOfType("int"), mock.AnythingOfType("int")).Return(nil, svrerr.ErrDBStorageFailed).Once()
		// Act
		s.Get("/userse", handler.GetUserList)
		w, err := s.Test(http.MethodGet, "/userse?limit=10&offset=10", nil)
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GetTotalUsersCount")
	})
}
