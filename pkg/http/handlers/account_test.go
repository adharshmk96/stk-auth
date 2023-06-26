package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	svrconfig "github.com/adharshmk96/stk-auth/pkg/infra/config"
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
		assert.Equal(t, http.StatusCreated, w.Code)

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
		assert.Equal(t, http.StatusBadRequest, w.Code)
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

		service.On("RegisterUser", mock.Anything).Return(nil, svrerr.ErrDBStoringData)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
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
		assert.Equal(t, http.StatusInternalServerError, w.Code)

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
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

type UserLogin struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func isCookieEquals(cookies []*http.Cookie, name, value string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value == value {
			return true
		}
	}
	return false
}

func TestLoginUserSession(t *testing.T) {

	uid := uuid.New()
	sid := uuid.NewString()
	userId := entities.UserID(uid)
	username := "user"
	password := "password"
	created := time.Now()
	updated := time.Now()

	login := UserLogin{
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

		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		// check if response has "message"
		var response stk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		ok := isCookieEquals(cookies, svrconfig.JWT_SESSION_COOKIE_NAME, sid)
		assert.True(t, ok)

	})

}

func TestLoginUserSessionToken(t *testing.T) {

	username := "test"
	password := "#Password123"

	login := UserLogin{
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

		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var response stk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		ok := isCookieEquals(cookies, svrconfig.JWT_SESSION_COOKIE_NAME, sessionToken)

		assert.True(t, ok)

	})

}

func TestGetSessionUser(t *testing.T) {

	uid := uuid.New()
	// sid := uuid.NewString()
	userId := entities.UserID(uid)
	username := "user"
	email := "user@email.com"
	password := "password"
	created := time.Now()
	updated := time.Now()

	userData := &entities.Account{
		ID:        userId,
		Email:     email,
		Username:  username,
		Password:  password,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	// sessionData := &entities.Session{
	// 	UserID:    userId,
	// 	CreatedAt: created,
	// 	UpdatedAt: updated,
	// 	SessionID: sid,
	// 	Valid:     true,
	// }

	t.Run("returns 200 and user details if session id is present in the cookie", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  svrconfig.SESSION_COOKIE_NAME,
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionId", mock.Anything).Return(userData, nil)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertCalled(t, "GetUserBySessionId", cookie.Value)
	})

	t.Run("returns 401 if session id is not present in the cookie", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
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

	login := UserLogin{
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
		assert.Equal(t, http.StatusBadRequest, w3.Code)

		var responseBody3 stk.Map
		json.Unmarshal(w3.Body.Bytes(), &responseBody3)
		assert.Equal(t, transport.INVALID_BODY, responseBody3["error"])

		// session login
		r := httptest.NewRequest("POST", "/login", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, transport.INVALID_BODY, responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", nil)
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBody2 stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBody2)
		assert.Equal(t, transport.INVALID_BODY, responseBody2["error"])

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

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, transport.INVALID_CREDENTIALS, responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusUnauthorized, w2.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, transport.INVALID_CREDENTIALS, responseBodyt["error"])

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

		invalidLogin := UserLogin{
			Username: "",
			Password: "",
		}

		body, _ := json.Marshal(invalidLogin)

		// session login
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, svrerr.ErrValidationFailed.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, svrerr.ErrValidationFailed.Error(), responseBodyt["error"])
	})

	t.Run("returns 500 if storage fails for some reason", func(t *testing.T) {
		config := &stk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := stk.NewServer(config)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSession", mock.Anything).Return(sessionData, svrerr.ErrDBRetrievingData)
		service.On("LoginUserSessionToken", mock.Anything).Return("", svrerr.ErrDBRetrievingData)

		s.Post("/login", handler.LoginUserSession)
		s.Post("/login/token", handler.LoginUserSessionToken)

		body, _ := json.Marshal(login)

		// session login
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var responseBody stk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, stk.ErrInternalServer.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusInternalServerError, w2.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt stk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, stk.ErrInternalServer.Error(), responseBodyt["error"])

	})
}
