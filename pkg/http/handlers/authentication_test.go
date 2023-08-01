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
	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
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

	userData := &entities.User{
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

		service := mocks.NewAuthenticationService(t)
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

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 if validation fails on data", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ whatever }`)

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 500 if there is storage error", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "` + email + `" }`)

		service := mocks.NewAuthenticationService(t)
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

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusInternalServerError, w.Code)

	})

	t.Run("returns 400 for invalid email", func(t *testing.T) {
		s := gsk.New()

		body := []byte(`{ "username": "` + username + `", "password": "` + password + `", "email": "invalid" }`)

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/register", handler.RegisterUser)

		w, _ := s.Test("POST", "/register", bytes.NewBuffer(body))

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestChangePassword(t *testing.T) {

	s := gsk.New()

	changeRequest := &transport.CredentialUpdateRequest{
		Credentials: &entities.User{
			Username: "user",
			Password: "#Password1",
		},
		NewCredentials: &entities.User{
			Username: "user",
			Email:    "bob@mail.com",
			Password: "#Password2",
		},
	}

	t.Run("returns 200 if password is changed successfully", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
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

		service := mocks.NewAuthenticationService(t)
		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrInvalidCredentials).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/change-password/b", handler.ChangeCredentials)

		body, _ := json.Marshal(changeRequest)

		w, _ := s.Test("POST", "/change-password/b", bytes.NewBuffer(body))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("returns 500 if change password fails", func(t *testing.T) {
		t.Run("authentication failed", func(t *testing.T) {

			service := mocks.NewAuthenticationService(t)
			service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrDBStorageFailed).Once()

			handler := handlers.NewUserManagementHandler(service)

			s.Post("/change-password/c", handler.ChangeCredentials)

			body, _ := json.Marshal(changeRequest)

			w, _ := s.Test("POST", "/change-password/c", bytes.NewBuffer(body))

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			service.AssertExpectations(t)
		})

		t.Run("change password failed", func(t *testing.T) {
			service := mocks.NewAuthenticationService(t)
			service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(nil).Once()
			service.On("ChangePassword", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrDBStorageFailed).Once()

			handler := handlers.NewUserManagementHandler(service)

			s.Post("/change-password/d", handler.ChangeCredentials)

			body, _ := json.Marshal(changeRequest)

			w, _ := s.Test("POST", "/change-password/d", bytes.NewBuffer(body))

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			service.AssertExpectations(t)
		})
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

	userData := &entities.User{
		ID:        userId,
		Username:  username,
		Password:  password,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	infra.LoadDefaultConfig()

	t.Run("returns 200 and session is retrieved for valid login", func(t *testing.T) {
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(nil).Once()
		service.On("CreateSession", mock.Anything).Return(sessionData, nil).Once()
		service.On("GetUserByID", userId.String()).Return(userData, nil).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

		assert.Equal(t, http.StatusOK, w.Code)
		service.AssertExpectations(t)

		// check if response has "message"
		var response gsk.Map
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, userData.ID.String(), response["id"])

		// check if cookie is set
		cookies := w.Result().Cookies()
		cookie := getCookie(cookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.NotEmpty(t, cookie)
		assert.Equal(t, sid, cookie.Value)
		assert.True(t, cookie.HttpOnly)

	})

	t.Run("return 401 when credentials are invalid", func(t *testing.T) {
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrInvalidCredentials).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrDBStorageFailed).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(nil).Once()
		service.On("CreateSession", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed).Once()

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(login)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/login", handler.LoginUserSession)

		body, _ := json.Marshal(gsk.Map{})
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(nil).Once()
		service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return(sessionToken, nil).Times(2)

		s.Post("/login", handler.LoginUserToken)

		body, _ := json.Marshal(login)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrInvalidCredentials).Once()

		s.Post("/login", handler.LoginUserToken)

		body, _ := json.Marshal(login)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
			s := gsk.New()

			service := mocks.NewAuthenticationService(t)
			handler := handlers.NewUserManagementHandler(service)

			service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(svrerr.ErrDBStorageFailed).Once()

			s.Post("/login", handler.LoginUserToken)

			body, _ := json.Marshal(login)
			w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
			s := gsk.New()

			service := mocks.NewAuthenticationService(t)
			handler := handlers.NewUserManagementHandler(service)

			service.On("Authenticate", mock.AnythingOfType("*entities.User")).Return(nil).Once()
			service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return("", jwt.ErrInvalidKey).Once()

			s.Post("/login", handler.LoginUserToken)

			body, _ := json.Marshal(login)
			w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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
		s := gsk.New()

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/login", handler.LoginUserToken)

		invalidLogin := map[string]interface{}{}

		body, _ := json.Marshal(invalidLogin)
		w, _ := s.Test("POST", "/login", bytes.NewBuffer(body))

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

	userData := &entities.User{
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

	s := gsk.New()

	infra.LoadDefaultConfig()

	t.Run("returns 200 and user details if session id is present in the cookie", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("GetUserBySessionId", mock.Anything).Return(userData, nil)

		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/a", handler.GetSessionUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}
		w, _ := s.Test("GET", "/user/a", nil, params)

		assert.Equal(t, http.StatusOK, w.Code)

		service.AssertExpectations(t)
	})

	t.Run("returns 401 if session id is not present in the cookie", func(t *testing.T) {
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/b", handler.GetSessionUser)

		w, _ := s.Test("GET", "/user/b", nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session id is empty in the cookie", func(t *testing.T) {
		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/ba", handler.GetSessionUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "",
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}

		w, _ := s.Test("GET", "/user/ba", nil, params)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session id is not valid", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("GetUserBySessionId", mock.Anything).Return(nil, svrerr.ErrInvalidSession)

		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/c", handler.GetSessionUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}
		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}

		w, _ := s.Test("GET", "/user/c", nil, params)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertExpectations(t)
	})

	t.Run("returns 500 if error occurs while getting user by session id", func(t *testing.T) {
		service := mocks.NewAuthenticationService(t)
		service.On("GetUserBySessionId", mock.Anything).Return(nil, svrerr.ErrDBEntryNotFound)

		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/d", handler.GetSessionUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}
		w, _ := s.Test("GET", "/user/d", nil, params)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		service.AssertExpectations(t)
	})
}

func TestGetTokenUser(t *testing.T) {

	uid := uuid.NewString()
	userId, _ := entities.ParseUserId(uid)
	username := "user"
	email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	userData := &entities.User{
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
		UserID: uid,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	s := gsk.New()

	accessToken := "access"
	refreshToken := "refresh"

	infra.LoadDefaultConfig()

	t.Run("returns 200 and user details if valid session token is present in the cookie", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("ValidateJWT", accessToken).Return(claims, nil).Once()
		service.On("GetUserByID", uid).Return(userData, nil).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/a", handler.GetTokenUser)

		atcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: accessToken,
		}

		rtcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
			Value: refreshToken,
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{
				atcookie,
				rtcookie,
			},
		}

		w, _ := s.Test("GET", "/user/a", nil, params)

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

		service.AssertNotCalled(t, "ValidateJWT", refreshToken)
	})

	t.Run("return 200 and cookie is access token expired", func(t *testing.T) {
		newToken := "new-token"

		service := mocks.NewAuthenticationService(t)

		service.On("ValidateJWT", accessToken).Return(claims, jwt.ErrTokenExpired)
		service.On("ValidateJWT", refreshToken).Return(claims, nil)
		service.On("GetUserByID", uid).Return(userData, nil).Once()
		service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return(newToken, nil).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/ab", handler.GetTokenUser)

		atcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: accessToken,
		}

		rtcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
			Value: refreshToken,
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{
				atcookie,
				rtcookie,
			},
		}

		w, _ := s.Test("GET", "/user/ab", nil, params)

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

		service := mocks.NewAuthenticationService(t)

		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		service.AssertNotCalled(t, "GetUserByID", mock.Anything)
		service.AssertNotCalled(t, "ValidateJWT", mock.Anything)

		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/b", handler.GetTokenUser)

		w, _ := s.Test("GET", "/user/b", nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if access token is invalid", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("ValidateJWT", accessToken).Return(nil, svrerr.ErrInvalidToken)
		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/c", handler.GetTokenUser)

		atcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: accessToken,
		}

		rtcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
			Value: refreshToken,
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{
				atcookie,
				rtcookie,
			},
		}

		w, _ := s.Test("GET", "/user/c", nil, params)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GetUserByID", mock.Anything)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		service.AssertNotCalled(t, "ValidateJWT", refreshToken)
	})

	t.Run("returns 401 if refresh token is expired", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("ValidateJWT", accessToken).Return(claims, jwt.ErrTokenExpired)
		service.On("ValidateJWT", refreshToken).Return(claims, jwt.ErrTokenExpired)
		service.On("GetUserByID", uid).Return(userData, nil).Once()
		handler := handlers.NewUserManagementHandler(service)

		s.Get("/user/d", handler.GetTokenUser)

		atcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: accessToken,
		}

		rtcookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
			Value: refreshToken,
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{
				atcookie,
				rtcookie,
			},
		}

		w, _ := s.Test("GET", "/user/d", nil, params)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		service.AssertExpectations(t)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
	})

	t.Run("return 500 if internal error occurs", func(t *testing.T) {

		t.Run("if validate jwt fails", func(t *testing.T) {
			service := mocks.NewAuthenticationService(t)
			service.On("ValidateJWT", accessToken).Return(nil, jwt.ErrInvalidKey)
			handler := handlers.NewUserManagementHandler(service)

			s.Get("/user/ac", handler.GetTokenUser)

			cookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
				Value: accessToken,
			}

			params := gsk.TestParams{
				Cookies: []*http.Cookie{cookie},
			}
			w, _ := s.Test("GET", "/user/ac", nil, params)

			assert.Equal(t, http.StatusInternalServerError, w.Code)

			service.AssertExpectations(t)
			service.AssertNotCalled(t, "GetUserByID", mock.Anything)
			service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		})

		t.Run("if get user by id fails", func(t *testing.T) {
			service := mocks.NewAuthenticationService(t)
			service.On("ValidateJWT", accessToken).Return(claims, nil).Once()
			service.On("GetUserByID", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed).Once()
			handler := handlers.NewUserManagementHandler(service)

			s.Get("/user/ad", handler.GetTokenUser)

			cookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
				Value: accessToken,
			}

			params := gsk.TestParams{
				Cookies: []*http.Cookie{cookie},
			}

			w, _ := s.Test("GET", "/user/ad", nil, params)

			assert.Equal(t, http.StatusInternalServerError, w.Code)

			service.AssertExpectations(t)
			service.AssertNotCalled(t, "GenerateJWT", mock.Anything)
		})

		// TODO FIX ME
		t.Run("if generate jwt fails", func(t *testing.T) {
			service := mocks.NewAuthenticationService(t)
			service.On("ValidateJWT", accessToken).Return(claims, jwt.ErrTokenExpired).Once()
			service.On("ValidateJWT", refreshToken).Return(claims, nil).Once()
			service.On("GetUserByID", mock.Anything).Return(userData, nil).Once()
			service.On("GenerateJWT", mock.AnythingOfType("*entities.CustomClaims")).Return("", jwt.ErrInvalidKey)
			handler := handlers.NewUserManagementHandler(service)

			s.Get("/user/bd", handler.GetTokenUser)

			atcookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
				Value: accessToken,
			}

			rtcookie := &http.Cookie{
				Name:  viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
				Value: refreshToken,
			}

			params := gsk.TestParams{
				Cookies: []*http.Cookie{
					atcookie,
					rtcookie,
				},
			}

			w, _ := s.Test("GET", "/user/bd", nil, params)

			assert.Equal(t, http.StatusInternalServerError, w.Code)

			service.AssertExpectations(t)
		})
	})
}

func TestLogoutUser(t *testing.T) {

	s := gsk.New()

	token := "abcdefg-asdfasdf"

	uid := uuid.NewString()

	// sessionData := &entities.Session{
	// 	UserID:    userId,
	// 	CreatedAt: created,
	// 	UpdatedAt: updated,
	// 	SessionID: sid,
	// 	Valid:     true,
	// }

	claims := &entities.CustomClaims{
		UserID: uid,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	infra.LoadDefaultConfig()
	t.Run("returns 200 service validates the session id in the cookie", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("LogoutUserBySessionId", token).Return(nil)

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/logout", handler.LogoutUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: token,
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}

		w, _ := s.Test("POST", "/logout", nil, params)

		assert.Equal(t, http.StatusOK, w.Code)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
		assert.Empty(t, wcookie.Value)
	})

	t.Run("returns 200 if valid access token is present in the cookie", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("ValidateJWT", token).Return(claims, nil).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/logout/a", handler.LogoutUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value: token,
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}

		w, _ := s.Test("POST", "/logout/a", nil, params)

		assert.Equal(t, http.StatusOK, w.Code)

		// check if cookie is set
		wcookies := w.Result().Cookies()
		wcookie := getCookie(wcookies, viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
		assert.Empty(t, wcookie.Value)

		service.AssertExpectations(t)
	})

	t.Run("returns 401 both session id and session token are absent in the cookie", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/logout/b", handler.LogoutUser)

		w, _ := s.Test("POST", "/logout/b", nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 401 if session id is invalid", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		service.On("LogoutUserBySessionId", mock.Anything).Return(svrerr.ErrInvalidSession).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/logout/c", handler.LogoutUser)

		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}

		w, _ := s.Test("POST", "/logout/c", nil, params)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		service.AssertExpectations(t)
	})

	t.Run("returns 500 if storage error occurs", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		cookie := &http.Cookie{
			Name:  viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
			Value: "abcdefg-asdfasdf",
		}
		service.On("LogoutUserBySessionId", cookie.Value).Return(svrerr.ErrDBStorageFailed).Once()

		handler := handlers.NewUserManagementHandler(service)

		s.Post("/logout/d", handler.LogoutUser)

		params := gsk.TestParams{
			Cookies: []*http.Cookie{cookie},
		}
		w, _ := s.Test("POST", "/logout/d", nil, params)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

	})

}

func TestCommonErrors(t *testing.T) {

	s := gsk.New()

	t.Run("returns 400 if request body is nil", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/login/a/token", handler.LoginUserToken)
		s.Post("/login/a", handler.LoginUserSession)
		s.Post("/register/a", handler.RegisterUser)

		// register
		w3, _ := s.Test("POST", "/register/a", nil)

		service.AssertNotCalled(t, "CreateUser", mock.Anything)
		assert.Equal(t, http.StatusBadRequest, w3.Code)

		var responseBody3 gsk.Map
		json.Unmarshal(w3.Body.Bytes(), &responseBody3)
		assert.Equal(t, transport.INVALID_BODY, responseBody3["error"])

		// session login
		w, _ := s.Test("POST", "/login/a", nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		service.AssertNotCalled(t, "LoginUserSession", mock.Anything)

		var responseBody gsk.Map
		json.Unmarshal(w.Body.Bytes(), &responseBody)
		assert.Equal(t, transport.INVALID_BODY, responseBody["error"])

		// session token login
		w2, _ := s.Test("POST", "/login/a/token", nil)

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)

		var responseBody2 gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBody2)
		assert.Equal(t, transport.INVALID_BODY, responseBody2["error"])

	})

	t.Run("return 400 if validation Fails", func(t *testing.T) {

		service := mocks.NewAuthenticationService(t)
		handler := handlers.NewUserManagementHandler(service)

		s.Post("/login/c/token", handler.LoginUserToken)

		invalidLogin := UserLogin{
			Username: "",
			Password: "",
		}

		body, _ := json.Marshal(invalidLogin)

		// session token login
		w2, _ := s.Test("POST", "/login/c/token", bytes.NewBuffer(body))

		assert.Equal(t, http.StatusBadRequest, w2.Code)
		service.AssertNotCalled(t, "GenerateJWT", mock.Anything)

		var responseBodyt gsk.Map
		json.Unmarshal(w2.Body.Bytes(), &responseBodyt)
		assert.Equal(t, svrerr.ErrValidationFailed.Error(), responseBodyt["error"])
	})

}
