package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegisterUser(t *testing.T) {

	uid := uuid.New()
	userId := entities.UserID(uid)
	username := "user"
	email := "user@email.com"
	password := "#Password1"
	created := time.Now()
	updated := time.Now()

	userData := &entities.Account{
		ID:        userId,
		Username:  username,
		Email:     email,
		Password:  password,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	expectedResponse := transport.UserResponse{
		ID:        userId.String(),
		Username:  username,
		Email:     email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns 201 and user data if user data is stored", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("CreateUser", mock.Anything).Return(userData, nil).Once()

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		assert.Equal(t, http.StatusCreated, w.Code)

		var response transport.UserResponse
		json.Unmarshal(w.Body.Bytes(), &response)

		assert.Equal(t, expectedResponse.ID, response.ID)
		assert.Equal(t, expectedResponse.Username, response.Username)
		assert.Equal(t, expectedResponse.Email, response.Email)
		assert.EqualValues(t, expectedResponse.CreatedAt.Unix(), response.CreatedAt.Unix())
		assert.EqualValues(t, expectedResponse.UpdatedAt.Unix(), response.UpdatedAt.Unix())

	})

	t.Run("returns 400 if email is empty", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `" }`)

		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 if validation fails on data", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ whatever }`)

		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 500 if there is storage error", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("CreateUser", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed).Once()

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertExpectations(t)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns 500 when passing userid in request body, fails decoding.", func(t *testing.T) {
		s := gsk.New()

		newUserId := uuid.NewString()

		body := []byte(`{ "id": "` + newUserId + `", "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusInternalServerError, w.Code)

	})

	t.Run("returns 400 for invalid email", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "invalid" }`)

		service := mocks.NewUserManagementService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestChangePassword(t *testing.T) {

	s := gsk.New()

	changeRequest := &transport.CredentialUpdate{
		Credentials: &entities.Account{
			Username: "user",
			Password: "#Password1",
		},
		NewCredentials: &entities.Account{
			Username: "user",
			Email:    "bob@mail.com",
			Password: "#Password2",
		},
	}

	t.Run("returns 200 if password is changed successfully", func(t *testing.T) {

		service := mocks.NewUserManagementService(t)
		service.On("Authenticate", changeRequest.Credentials).Return(nil).Once()
		service.On("ChangePassword", changeRequest.NewCredentials).Return(nil).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/change-password/a", handler.ChangeCredentials)

		body, _ := json.Marshal(changeRequest)

		w, _ := s.Test("POST", "/change-password/a", bytes.NewBuffer(body))

		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("returns 401 if authentication failed", func(t *testing.T) {

		service := mocks.NewUserManagementService(t)
		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrInvalidCredentials).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/change-password/b", handler.ChangeCredentials)

		body, _ := json.Marshal(changeRequest)

		w, _ := s.Test("POST", "/change-password/b", bytes.NewBuffer(body))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("returns 500 if change password fails", func(t *testing.T) {
		t.Run("authentication failed", func(t *testing.T) {

			service := mocks.NewUserManagementService(t)
			service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrDBStorageFailed).Once()

			handler := handlers.NewUserManagementHandler(service)

			s.Post("/change-password/c", handler.ChangeCredentials)

			body, _ := json.Marshal(changeRequest)

			w, _ := s.Test("POST", "/change-password/c", bytes.NewBuffer(body))

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			service.AssertExpectations(t)
		})

		t.Run("change password failed", func(t *testing.T) {
			service := mocks.NewUserManagementService(t)
			service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(nil).Once()
			service.On("ChangePassword", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrDBStorageFailed).Once()

			handler := handlers.NewUserManagementHandler(service)

			s.Post("/change-password/d", handler.ChangeCredentials)

			body, _ := json.Marshal(changeRequest)

			w, _ := s.Test("POST", "/change-password/d", bytes.NewBuffer(body))

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			service.AssertExpectations(t)
		})
	})

}
