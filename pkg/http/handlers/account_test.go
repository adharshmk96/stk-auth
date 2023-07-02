package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/google/uuid"
	"github.com/spf13/viper"
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
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

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
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

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
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("RegisterUser", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns 500 when passing userid in request body, fails decoding.", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

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
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

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

func getCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return &http.Cookie{}
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
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

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
		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.NotEmpty(t, cookie)
		assert.Equal(t, sid, cookie.Value)
		assert.True(t, cookie.HttpOnly)

	})

}

func TestLoginUserSessionToken(t *testing.T) {

	username := "test"
	password := "#Password123"

	login := UserLogin{
		Username: username,
		Password: password,
	}

	sessionToken := "header.claims.signature"

	t.Run("returns 200 and session token is returned when login is valid", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

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

		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME))
		assert.NotEmpty(t, cookie)
		assert.Equal(t, sessionToken, cookie.Value)
		assert.True(t, cookie.HttpOnly)
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

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	t.Run("returns 200 and user details if session id is present in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/a", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user/a", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionId", mock.Anything).Return(userData, nil)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertCalled(t, "GetUserBySessionId", cookie.Value)
	})

	t.Run("returns 401 if session id is not present in the cookie", func(t *testing.T) {
		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/b", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user/b", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session id is not valid", func(t *testing.T) {
		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/c", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user/c", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionId", mock.Anything).Return(nil, svrerr.ErrInvalidSession)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 500 if error occurs while getting user by session id", func(t *testing.T) {
		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/d", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user/d", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionId", mock.Anything).Return(nil, svrerr.ErrDBEntryNotFound)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestGetSessionTokenUser(t *testing.T) {

	uid := uuid.New()
	// sid := uuid.NewString()
	userId := entities.UserID(uid)
	username := "user"
	email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	userData := &entities.Account{
		ID:        userId,
		Email:     email,
		Username:  username,
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

	accountWithToken := &entities.AccountWithToken{
		Account: *userData,
		Token:   "abcdefg-asdfasdf",
	}

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	t.Run("returns 200 and user details if valid session token is present in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/a", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/a", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionToken", mock.Anything).Return(accountWithToken, nil)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertCalled(t, "GetUserBySessionToken", cookie.Value)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME))
		assert.NotEmpty(t, wcookie)
		assert.Equal(t, accountWithToken.Token, wcookie.Value)
		assert.True(t, wcookie.HttpOnly)
	})

	t.Run("returns 401 if session token is not present in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/b", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/b", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session token is invalid", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/c", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/c", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionToken", mock.Anything).Return(nil, svrerr.ErrInvalidToken)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertCalled(t, "GetUserBySessionToken", cookie.Value)
	})

	t.Run("returns 401 if session is invalid", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/d", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/d", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionToken", mock.Anything).Return(nil, svrerr.ErrInvalidSession)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertCalled(t, "GetUserBySessionToken", cookie.Value)
	})

	t.Run("return 500 if storage error occurs", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/e", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/e", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("GetUserBySessionToken", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		service.AssertCalled(t, "GetUserBySessionToken", cookie.Value)
	})
}

func TestLogoutUser(t *testing.T) {

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	t.Run("returns 200 service validates the session id in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("LogoutUserBySessionId", mock.Anything).Return(nil)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertCalled(t, "LogoutUserBySessionId", cookie.Value)
		service.AssertNotCalled(t, "LogoutUserBySessionToken", mock.Anything)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.Empty(t, wcookie.Value)
	})

	t.Run("returns 200 if valid session token is present in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout/a", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout/a", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("LogoutUserBySessionToken", mock.Anything).Return(nil)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertCalled(t, "LogoutUserBySessionToken", cookie.Value)
		service.AssertNotCalled(t, "LogoutUserBySessionId", mock.Anything)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME))
		assert.Empty(t, wcookie.Value)
	})

	t.Run("returns 401 both session id and session token are absent in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout/b", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout/b", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session id is invalid", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout/c", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout/c", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("LogoutUserBySessionId", mock.Anything).Return(svrerr.ErrInvalidSession)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertCalled(t, "LogoutUserBySessionId", cookie.Value)
		service.AssertNotCalled(t, "LogoutUserBySessionToken", mock.Anything)
	})

	t.Run("returns 500 if storage error occurs", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout/d", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout/d", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("LogoutUserBySessionToken", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		service.AssertCalled(t, "LogoutUserBySessionToken", cookie.Value)
		service.AssertNotCalled(t, "LogoutUserBySessionId", mock.Anything)
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

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	t.Run("returns 400 if request body is nil", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/a/token", handler.LoginUserSessionToken)
		s.Post("/login/a", handler.LoginUserSession)
		s.Post("/register/a", handler.RegisterUser)

		// register
		r3 := httptest.NewRequest("POST", "/register/a", nil)
		w3 := httptest.NewRecorder()

		s.Router.ServeHTTP(w3, r3)

		service.AssertNotCalled(t, "RegisterUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w3.Code)

		var responseBody3 gsk.Map
		json.Unmarshal(w3.Body.Bytes(), &responseBody3)
		assert.Equal(t, transport.INVALID_BODY, responseBody3["error"])

		// session login
		r := httptest.NewRequest("POST", "/login/a", nil)
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		var responseBody gsk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, transport.INVALID_BODY, responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/a/token", nil)
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBody2 gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBody2)
		assert.Equal(t, transport.INVALID_BODY, responseBody2["error"])

	})

	t.Run("returns 401 for invalid credentials", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/token/b", handler.LoginUserSessionToken)
		s.Post("/login/b", handler.LoginUserSession)

		body, _ := json.Marshal(login)

		// session login
		r := httptest.NewRequest("POST", "/login/b", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		service.On("LoginUserSession", mock.Anything).Return(sessionData, svrerr.ErrInvalidCredentials)
		service.On("LoginUserSessionToken", mock.Anything).Return("", svrerr.ErrInvalidCredentials)

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var responseBody gsk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, transport.INVALID_CREDENTIALS, responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/token/b", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusUnauthorized, w2.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, transport.INVALID_CREDENTIALS, responseBodyt["error"])

	})

	t.Run("return 400 if validation Fails", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/c/token", handler.LoginUserSessionToken)
		s.Post("/login/c", handler.LoginUserSession)

		invalidLogin := UserLogin{
			Username: "",
			Password: "",
		}

		body, _ := json.Marshal(invalidLogin)

		// session login
		r := httptest.NewRequest("POST", "/login/c", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var responseBody gsk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, svrerr.ErrValidationFailed.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/c/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, svrerr.ErrValidationFailed.Error(), responseBodyt["error"])
	})

	t.Run("returns 500 if storage fails for some reason", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("LoginUserSession", mock.Anything).Return(sessionData, svrerr.ErrDBStorageFailed)
		service.On("LoginUserSessionToken", mock.Anything).Return("", svrerr.ErrDBStorageFailed)

		s.Post("/login/d", handler.LoginUserSession)
		s.Post("/login/d/token", handler.LoginUserSessionToken)

		body, _ := json.Marshal(login)

		// session login
		r := httptest.NewRequest("POST", "/login/d", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.Router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		service.AssertCalled(t, "LoginUserSession", mock.Anything)

		var responseBody gsk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, gsk.ErrInternalServer.Error(), responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/d/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.Router.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusInternalServerError, w2.Code)
		service.AssertCalled(t, "LoginUserSessionToken", mock.Anything)

		var responseBodyt gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, gsk.ErrInternalServer.Error(), responseBodyt["error"])

	})
}
