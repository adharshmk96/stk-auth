package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
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

	t.Run("returns 400 if validation fails on data", func(t *testing.T) {
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

	t.Run("returns 500 if there is storage error", func(t *testing.T) {
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

	t.Run("returns 500 when passing userid, fails decoding.", func(t *testing.T) {
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

	t.Run("returns 400 for invalid email", func(t *testing.T) {
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

	t.Run("returns 200 and session is retrieved for valid login", func(t *testing.T) {
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

		// check if response has "message"
		var response stk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		cookie := w.Result().Cookies()[0]
		assert.Equal(t, sid, cookie.Value)

	})

}

func TestLoginUserSessionToken(t *testing.T) {

	username := "test"
	password := "#Password123"

	login := &transport.UserLogin{
		Username: username,
		Password: password,
	}

	sessionToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdXRoLXNlcnZlciIsImV4cCI6MTY4Nzg0NzAzNiwiaWF0IjoxNjg3NzYwNjM2LCJpc3MiOiJhdXRoLXNlcnZlciIsInN1YiI6ImF1dGhlbnRpY2F0aW9uIn0.fJzia9f1GzpfUQXSW2v-7AXyq8kg0OncdEzgOS2PZziCU4-u3-4kgHzigZCeUQjD3xBL8nOMSDeWEo669es8z6NIbtlMsA4Jh4pQ3_a1AIhMa9mdyQl0CfOhReNHlYOkFZUUSjGs5DY2XwixnN4jJe7gkZv_LyBaroEoZ918DOaFeVpqTct_EUu8G_24HX4AnXL4NISwVe3KOtSiNvFi1xIicnUi0W4hwHvi5S3S_3oGtUb-AmBoWUMof_sUs3xmo46vpevgvjV8SDsDUMtOEuJw4gXAqGL9FksD3QS1mvq3tOH7cGtvCtI7QjuGXTA40nLNe05KMUDP2sv_Rshj0g"

	t.Run("returns 200 and session token is returned when login is valid", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSessionToken", mock.Anything).Return(sessionToken, nil)

		s.Post("/login", handler.LoginUserSessionToken)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 200, w.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var response stk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		jwtCookie := w.Result().Cookies()[0].Value

		assert.Equal(t, sessionToken, jwtCookie)

	})

}

func TestCommonErrors(t *testing.T) {

	uid := uuid.New()
	sid := uuid.NewString()
	userId := entities.UserID(uid)
	created := time.Now()
	updated := time.Now()

	username := "test"
	password := "#Password123"

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

	t.Run("returns 400 if request body is nil", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/token", handler.LoginUserSessionToken)
		s.Post("/login", handler.LoginUserSession)
		s.Post("/register", handler.RegisterUser)

		// register
		r3 := httptest.NewRequest("POST", "/register", nil)
		w3 := httptest.NewRecorder()

		s.Router.ServeHTTP(w3, r3)

		service.AssertNotCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, 400, w3.Code)

		var responseBody3 stk.Map
		json.Unmarshal(w3.Body.Bytes(), &responseBody3)
		assert.Equal(t, stk.ErrInvalidJSON.Error(), responseBody3["error"])

		// session login
		r := httptest.NewRequest("POST", "/login", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 400, w.Code)
		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, stk.ErrInvalidJSON.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", nil)
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, 400, w2.Code)
		service.AssertNotCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBody2 stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBody2)
		assert.Equal(t, stk.ErrInvalidJSON.Error(), responseBody2["error"])

	})

	t.Run("returns 401 for invalid credentials", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/token", handler.LoginUserSessionToken)
		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)

		// session login
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		service.On("LoginUserSession", mock.Anything).Return(sessionData, svrerr.ErrInvalidCredentials)
		service.On("LoginUserSessionToken", mock.Anything).Return("", svrerr.ErrInvalidCredentials)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 401, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, svrerr.ErrInvalidCredentials.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, 401, w2.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, svrerr.ErrInvalidCredentials.Error(), responseBodyt["error"])

	})

	t.Run("return 400 if validation Fails", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/token", handler.LoginUserSessionToken)
		s.Post("/login", handler.LoginUserSession)

		invalidLogin := &transport.UserLogin{
			Username: "",
			Password: "",
		}

		body, _ := json.Marshal(invalidLogin)

		// session login
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		assert.Equal(t, 400, w.Code)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, svrerr.ErrInvalidData.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, 400, w2.Code)
		service.AssertNotCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, svrerr.ErrInvalidData.Error(), responseBodyt["error"])
	})

	t.Run("returns 500 if storage fails for some reason", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSession", mock.Anything).Return(sessionData, svrerr.ErrRetrievingData)
		service.On("LoginUserSessionToken", mock.Anything).Return("", svrerr.ErrRetrievingData)

		s.Post("/login", handler.LoginUserSession)
		s.Post("/login/token", handler.LoginUserSessionToken)

		body, _ := json.Marshal(login)

		// session login
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, 500, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, stk.ErrInternalServer.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, 500, w2.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, stk.ErrInternalServer.Error(), responseBodyt["error"])

	})
}
