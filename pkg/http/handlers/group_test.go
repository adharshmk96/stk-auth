package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateGroup(t *testing.T) {

	s := gsk.New()

	t.Run("should return 400 if body is invalid", func(t *testing.T) {
		// Arrange
		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)
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
		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)
		group := &entities.UserGroup{
			Name:        "test",
			Description: "test",
		}
		body, _ := json.Marshal(group)

		service.On("CreateGroup", mock.AnythingOfType("*entities.UserGroup")).Return(group, nil)
		// Act
		s.Post("/groups/a", handler.CreateGroup)

		w, err := s.Test(http.MethodPost, "/groups/a", bytes.NewBuffer(body))
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, w.Code)

		service.AssertExpectations(t)
	})
	t.Run("should return 500 if group is not created", func(t *testing.T) {
		// Arrange
		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)
		group := &entities.UserGroup{
			Name:        "test",
			Description: "test",
		}
		body, _ := json.Marshal(group)

		service.On("CreateGroup", mock.AnythingOfType("*entities.UserGroup")).Return(nil, svrerr.ErrDBStorageFailed)
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
		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)
		group := &entities.UserGroup{
			Name:        "test",
			Description: "test",
		}
		body, _ := json.Marshal(group)

		service.On("CreateGroup", mock.AnythingOfType("*entities.UserGroup")).Return(nil, svrerr.ErrDBDuplicateEntry)
		// Act
		s.Post("/groups/c", handler.CreateGroup)

		w, err := s.Test(http.MethodPost, "/groups/c", bytes.NewBuffer(body))
		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, w.Code)

		service.AssertExpectations(t)
	})
}
