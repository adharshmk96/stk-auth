package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adharshmk96/auth-server/mocks"
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/http/handlers"
	"github.com/adharshmk96/auth-server/pkg/http/transport"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk"
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
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("RegisterUser", mock.Anything).Return(userData, nil)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, 201, w.Code)

		var response transport.UserResponse
		json.Unmarshal(w.Body.Bytes(), &response)

		assert.Equal(t, expectedResponse.ID, response.ID)
		assert.Equal(t, expectedResponse.Username, response.Username)
		assert.Equal(t, expectedResponse.Email, response.Email)
		assert.EqualValues(t, expectedResponse.CreatedAt.Unix(), response.CreatedAt.Unix())
		assert.EqualValues(t, expectedResponse.UpdatedAt.Unix(), response.UpdatedAt.Unix())

	})

	t.Run("returns 400 if user data is invalid", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		body := []byte(`{ whatever }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertNotCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, 400, w.Code)
	})

	t.Run("returns 500 if user data is not stored", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("RegisterUser", mock.Anything).Return(nil, svrerr.ErrStoringData)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, 500, w.Code)
	})

	t.Run("passing userid will fail the decoding.", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		newUserId := uuid.NewString()

		body := []byte(`{ "id": "` + newUserId + `", "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertNotCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, 500, w.Code)

	})

	t.Run("invalid email returns 400", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "invalid" }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertNotCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, 400, w.Code)
	})
}

func TestLoginUserSession(t *testing.T) {

	uid := uuid.New()
	sid := uuid.NewString()
	userId := entities.UserID(uid)
	username := "user"
	password := "password"
	created := time.Now()
	updated := time.Now()

	login := &transport.UserLogin{
		Username: username,
		Password: password,
	}

	sessionData := &entities.Session{
		UserID:    userId,
		CreatedAt: created,
		UpdatedAt: updated,
		SessionID: sid,
		Valid:     true,
	}

	t.Run("returns 200 and session is retrieved", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSession", mock.Anything).Return(sessionData, nil)

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 200, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var response transport.SessionResponse
		json.Unmarshal(w.Body.Bytes(), &response)

		assert.Equal(t, userId.String(), response.UserID)
		assert.NotNil(t, response.SessionID)
		assert.EqualValues(t, created.Unix(), response.CreatedAt.Unix())
		assert.EqualValues(t, updated.Unix(), response.UpdatedAt.Unix())

	})

	t.Run("returns 400 if invalid request body", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login", handler.LoginUserSession)

		r := httptest.NewRequest("POST", "/login", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 400, w.Code)
		service.AssertNotCalled(t, "LoginUser", mock.Anything)

	})

	t.Run("returns 401 if invalid credentials", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSession", mock.Anything).Return(nil, svrerr.ErrInvalidCredentials)

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 401, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

	})

	t.Run("return 400 if validation Fails", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login", handler.LoginUserSession)

		invalidLogin := &transport.UserLogin{
			Username: "",
			Password: "",
		}

		body, _ := json.Marshal(invalidLogin)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 400, w.Code)
		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)
	})

	t.Run("returns 500 if retreval fails for some reason", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSession", mock.Anything).Return(nil, svrerr.ErrRetrievingData)

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 500, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

	})

}
