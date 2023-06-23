package handlers_test

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/adharshmk96/auth-server/mocks"
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/http/handlers"
	"github.com/adharshmk96/auth-server/pkg/storage/sqlite"
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
	password := "password"

	userData := &entities.Account{
		ID:       userId,
		Username: username,
		Email:    email,
		Password: password,
	}

	t.Run("returns 200 and user data if user data is stored", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)
		want := []byte(`{"id":"` + uid.String() + `","username":"` + username + `","email":"` + email + `"}`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("RegisterUser", mock.Anything).Return(userData, nil)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, want, w.Body.Bytes())
		service.AssertCalled(t, "RegisterUser", mock.Anything)

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

		assert.Equal(t, 400, w.Code)
		service.AssertNotCalled(t, "RegisterUser", mock.Anything)
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

		service.On("RegisterUser", mock.Anything).Return(nil, sqlite.ErrStoringAccount)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 500, w.Code)
		service.AssertCalled(t, "RegisterUser", mock.Anything)
	})
}
