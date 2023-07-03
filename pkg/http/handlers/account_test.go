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
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/golang-jwt/jwt/v5"
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

		service.On("CreateUser", mock.Anything).Return(userData, nil).Once()

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

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
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `" }`)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
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

		s.GetRouter().ServeHTTP(w, r)

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
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

		service.On("CreateUser", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed).Once()

		s.Post("/register", handler.RegisterUser)

		r := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		service.AssertExpectations(t)
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

		s.GetRouter().ServeHTTP(w, r)

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
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

		s.GetRouter().ServeHTTP(w, r)

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
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

	infra.LoadDefaultConfig()

	t.Run("returns 200 and session is retrieved for valid login", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(nil).Once()
		service.On("CreateSession", mock.Anything).Return(sessionData, nil).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)

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

	t.Run("return 401 when credentials are invalid", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrInvalidCredentials).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertExpectations(t)

		// check if response has "error"
		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.INVALID_CREDENTIALS, response["error"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.Empty(t, cookie)

		service.AssertNotCalled(t, "CreateSession", mock.Anything)
	})

	t.Run("return 500 when error occurs during authenticate", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrDBStorageFailed).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		service.AssertExpectations(t)

		// check if response has "error"
		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.INTERNAL_SERVER_ERROR, response["error"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.Empty(t, cookie)

		service.AssertNotCalled(t, "CreateSession", mock.Anything)
	})

	t.Run("return 500 when error occurs during create session", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(nil).Once()
		service.On("CreateSession", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		service.AssertExpectations(t)

		// check if response has "error"
		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.INTERNAL_SERVER_ERROR, response["error"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.Empty(t, cookie)

	})

	t.Run("return 400 when validation fails", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(gsk.Map{})
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertExpectations(t)

		// check if response has "error"
		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.VALIDATION_FAILED, response["error"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.Empty(t, cookie)

		service.AssertNotCalled(t, "CreateSession", mock.Anything)
	})

}

func TestLoginUserToken(t *testing.T) {

	username := "user"
	password := "password"

	login := UserLogin{
		Username: username,
		Password: password,
	}

	sessionToken := "header.claims.signature"

	infra.LoadDefaultConfig()

	t.Run("returns 200 and session token is returned when login is valid", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(nil).Once()
		service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return(sessionToken, nil).Times(2)

		s.Post("/login", handler.LoginUserToken)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)

		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.SUCCESS_LOGIN, response["message"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		access_cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
		refresh_cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME))
		assert.NotEmpty(t, access_cookie)
		assert.Equal(t, sessionToken, access_cookie.Value)
		assert.True(t, access_cookie.HttpOnly)

		assert.NotEmpty(t, refresh_cookie)
		assert.Equal(t, sessionToken, refresh_cookie.Value)
		assert.True(t, refresh_cookie.HttpOnly)

		service.AssertExpectations(t)
	})

	t.Run("returns 401 when login is invalid", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrInvalidCredentials).Once()

		s.Post("/login", handler.LoginUserToken)

		body, _ := json.Marshal(login)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertExpectations(t)

		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.INVALID_CREDENTIALS, response["error"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
		assert.Empty(t, cookie)

		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
	})

	t.Run("returns 500 when internal error occurs", func(t *testing.T) {

		t.Run("when db error in Authenticate", func(t *testing.T) {
			stkconfig := &gsk.ServerConfig{
				Port:           "8080",
				RequestLogging: false,
			}
			s := gsk.NewServer(stkconfig)

			service := mocks.NewAccountService(t)
			handler := handlers.NewAccountHandler(service)

			service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(svrerr.ErrDBStorageFailed).Once()

			s.Post("/login", handler.LoginUserToken)

			body, _ := json.Marshal(login)
			r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			s.GetRouter().ServeHTTP(w, r)

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			service.AssertExpectations(t)

			var response gsk.Map
			json.Unmarshal(w.Body.Bytes(), &response)
			assert.Equal(t, transport.INTERNAL_SERVER_ERROR, response["error"])

			// check if cookie is set
			cookies := w.Result().Cookies()
			cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
			assert.Empty(t, cookie)

			service.AssertExpectations(t)
			service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		})

		t.Run("when some error in GenerateJWT", func(t *testing.T) {
			stkconfig := &gsk.ServerConfig{
				Port:           "8080",
				RequestLogging: false,
			}
			s := gsk.NewServer(stkconfig)

			service := mocks.NewAccountService(t)
			handler := handlers.NewAccountHandler(service)

			service.On("Authenticate", mock.AnythingOfType("*entities.Account")).Return(nil).Once()
			service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return("", jwt.ErrInvalidKey).Once()

			s.Post("/login", handler.LoginUserToken)

			body, _ := json.Marshal(login)
			r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			s.GetRouter().ServeHTTP(w, r)

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			service.AssertExpectations(t)

			var response gsk.Map
			json.Unmarshal(w.Body.Bytes(), &response)
			assert.Equal(t, transport.INTERNAL_SERVER_ERROR, response["error"])

			// check if cookie is set
			cookies := w.Result().Cookies()
			cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
			assert.Empty(t, cookie)

			service.AssertExpectations(t)
		})

	})

	t.Run("returns 400 if invalid request body", func(t *testing.T) {
		stkconfig := &gsk.ServerConfig{
			Port:           "8080",
			RequestLogging: false,
		}
		s := gsk.NewServer(stkconfig)

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login", handler.LoginUserToken)

		invalidLogin := map[string]interface{}{}

		body, _ := json.Marshal(invalidLogin)
		r := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertExpectations(t)

		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, transport.VALIDATION_FAILED, response["error"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
		assert.Empty(t, cookie)

		service.AssertExpectations(t)
		service.AssertNotCalled(t, "Authenticate", mock.Anything)
		service.AssertNotCalled(t, "CreateSession", mock.Anything)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
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

	infra.LoadDefaultConfig()

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

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertCalled(t, "GetUserBySessionId", cookie.Value)
	})

	t.Run("returns 401 if session id is not present in the cookie", func(t *testing.T) {
		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/b", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user/b", nil)
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session id is empty in the cookie", func(t *testing.T) {
		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/ba", handler.GetSessionUser)

		r := httptest.NewRequest("GET", "/user/ba", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "",
		}

		r.AddCookie(cookie)
		s.GetRouter().ServeHTTP(w, r)

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

		s.GetRouter().ServeHTTP(w, r)

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

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestGetSessionTokenUser(t *testing.T) {

	uid := uuid.NewString()
	sid := uuid.NewString()
	userId, _ := entities.ParseUserId(uid)
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

	claims := &entities.CustomClaims{
		UserID:    uid,
		SessionID: sid,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	token := "abcdefg-asdfasdf"

	infra.LoadDefaultConfig()

	t.Run("returns 200 and user details if valid session token is present in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/a", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/a", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: token,
		}

		r.AddCookie(cookie)
		service.On("ValidateJWT", token).Return(claims, nil).Once()
		service.On("GetUserBySessionId", sid).Return(userData, nil).Once()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		// // check if cookie is set
		// wcookies := w.Result().Cookies()
		// wcookie := getCookie(wcookies, viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME))
		// assert.NotEmpty(t, wcookie)
		// assert.Equal(t, token, wcookie.Value)
		// assert.True(t, wcookie.HttpOnly)

		// check if response body is correct
		var respBody map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &respBody)
		assert.NoError(t, err)
		assert.Equal(t, uid, respBody["id"])
		assert.Equal(t, username, respBody["username"])
		assert.Equal(t, email, respBody["email"])
		service.AssertExpectations(t)
	})

	t.Run("return 200 and cookie is set if valid token expired", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/ab", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/ab", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: token,
		}

		newToken := "new-token"

		r.AddCookie(cookie)
		service.On("ValidateJWT", token).Return(claims, jwt.ErrTokenExpired).Once()
		service.On("GetUserBySessionId", sid).Return(userData, nil).Once()
		service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return(newToken, nil).Once()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
		assert.NotEmpty(t, wcookie)
		assert.Equal(t, newToken, wcookie.Value)
		assert.True(t, wcookie.HttpOnly)

		// check if response body is correct
		var respBody map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &respBody)
		assert.NoError(t, err)
		assert.Equal(t, uid, respBody["id"])
		assert.Equal(t, username, respBody["username"])
		assert.Equal(t, email, respBody["email"])
		service.AssertExpectations(t)
	})

	t.Run("returns 401 if session token is not present in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/b", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/b", nil)
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		service.AssertNotCalled(t, "GetUserBySessionId", mock.Anything)
		service.AssertNotCalled(t, "ValidateJWT", mock.Anything)
	})

	t.Run("returns 401 if session token is invalid", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/c", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/c", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: token,
		}

		r.AddCookie(cookie)
		service.On("ValidateJWT", token).Return(nil, svrerr.ErrInvalidToken)

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GetUserBySessionId", mock.Anything)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
	})

	t.Run("returns 401 if session is invalid", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Get("/user/d", handler.GetSessionTokenUser)

		r := httptest.NewRequest("GET", "/user/d", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("ValidateJWT", token).Return(claims, nil).Once()
		service.On("GetUserBySessionId", mock.Anything).Return(nil, svrerr.ErrInvalidSession).Once()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
	})

	t.Run("return 500 if internal error occurs", func(t *testing.T) {

		t.Run("if validate jwt fails", func(t *testing.T) {
			service := mocks.NewAccountService(t)
			handler := handlers.NewAccountHandler(service)

			s.Get("/user/ac", handler.GetSessionTokenUser)

			r := httptest.NewRequest("GET", "/user/ac", nil)
			w := httptest.NewRecorder()

			cookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
				Value: token,
			}

			r.AddCookie(cookie)
			service.On("ValidateJWT", token).Return(nil, jwt.ErrInvalidKey)

			s.GetRouter().ServeHTTP(w, r)

			assert.Equal(t, http.StatusInternalServerError, w.Code)

			service.AssertExpectations(t)
			service.AssertNotCalled(t, "GetUserBySessionId", mock.Anything)
			service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		})

		t.Run("if get user by session id fails", func(t *testing.T) {
			service := mocks.NewAccountService(t)
			handler := handlers.NewAccountHandler(service)

			s.Get("/user/ad", handler.GetSessionTokenUser)

			r := httptest.NewRequest("GET", "/user/ad", nil)
			w := httptest.NewRecorder()

			cookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
				Value: "abcdefg-asdfasdf",
			}

			r.AddCookie(cookie)
			service.On("ValidateJWT", token).Return(claims, nil).Once()
			service.On("GetUserBySessionId", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed).Once()

			s.GetRouter().ServeHTTP(w, r)

			assert.Equal(t, http.StatusInternalServerError, w.Code)

			service.AssertExpectations(t)
			service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		})

		t.Run("if generate jwt fails", func(t *testing.T) {
			service := mocks.NewAccountService(t)
			handler := handlers.NewAccountHandler(service)

			s.Get("/user/bd", handler.GetSessionTokenUser)

			r := httptest.NewRequest("GET", "/user/bd", nil)
			w := httptest.NewRecorder()

			cookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
				Value: "abcdefg-asdfasdf",
			}

			r.AddCookie(cookie)
			service.On("ValidateJWT", token).Return(claims, jwt.ErrTokenExpired).Once()
			service.On("GetUserBySessionId", mock.Anything).Return(userData, nil).Once()
			service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return("", jwt.ErrInvalidKey)

			s.GetRouter().ServeHTTP(w, r)

			assert.Equal(t, http.StatusInternalServerError, w.Code)

			service.AssertExpectations(t)
		})
	})
}

func TestLogoutUser(t *testing.T) {

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	token := "abcdefg-asdfasdf"

	uid := uuid.NewString()
	sid := uuid.NewString()

	// sessionData := &entities.Session{
	// 	UserID:    userId,
	// 	CreatedAt: created,
	// 	UpdatedAt: updated,
	// 	SessionID: sid,
	// 	Valid:     true,
	// }

	claims := &entities.CustomClaims{
		UserID:    uid,
		SessionID: sid,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	infra.LoadDefaultConfig()
	t.Run("returns 200 service validates the session id in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: token,
		}

		r.AddCookie(cookie)
		service.On("LogoutUserBySessionId", token).Return(nil)

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

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
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: token,
		}

		r.AddCookie(cookie)
		service.On("ValidateJWT", token).Return(claims, nil).Once()
		service.On("LogoutUserBySessionId", mock.Anything).Return(nil)

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
		assert.Empty(t, wcookie.Value)

		service.AssertExpectations(t)
	})

	t.Run("returns 401 both session id and session token are absent in the cookie", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout/b", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout/b", nil)
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

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
		service.On("LogoutUserBySessionId", mock.Anything).Return(svrerr.ErrInvalidSession).Once()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("returns 500 if storage error occurs", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/logout/d", handler.LogoutUser)

		r := httptest.NewRequest("POST", "/logout/d", nil)
		w := httptest.NewRecorder()

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		r.AddCookie(cookie)
		service.On("LogoutUserBySessionId", cookie.Value).Return(svrerr.ErrDBStorageFailed).Once()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

	})

}

func TestCommonErrors(t *testing.T) {

	stkconfig := &gsk.ServerConfig{
		Port:           "8080",
		RequestLogging: false,
	}
	s := gsk.NewServer(stkconfig)

	t.Run("returns 400 if request body is nil", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/a/token", handler.LoginUserToken)
		s.Post("/login/a", handler.LoginUserSession)
		s.Post("/register/a", handler.RegisterUser)

		// register
		r3 := httptest.NewRequest("POST", "/register/a", nil)
		w3 := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w3, r3)

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w3.Code)

		var responseBody3 gsk.Map
		json.Unmarshal(w3.Body.Bytes(), &responseBody3)
		assert.Equal(t, transport.INVALID_BODY, responseBody3["error"])

		// session login
		r := httptest.NewRequest("POST", "/login/a", nil)
		w := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		var responseBody gsk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, transport.INVALID_BODY, responseBody["error"])

		// session token login
		r2 := httptest.NewRequest("POST", "/login/a/token", nil)
		w2 := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)

		var responseBody2 gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBody2)
		assert.Equal(t, transport.INVALID_BODY, responseBody2["error"])

	})

	t.Run("return 400 if validation Fails", func(t *testing.T) {

		service := mocks.NewAccountService(t)
		handler := handlers.NewAccountHandler(service)

		s.Post("/login/c/token", handler.LoginUserToken)

		invalidLogin := UserLogin{
			Username: "",
			Password: "",
		}

		body, _ := json.Marshal(invalidLogin)

		// session token login
		r2 := httptest.NewRequest("POST", "/login/c/token", bytes.NewBuffer(body))
		w2 := httptest.NewRecorder()

		s.GetRouter().ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)

		var responseBodyt gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, svrerr.ErrValidationFailed.Error(), responseBodyt["error"])
	})

}
