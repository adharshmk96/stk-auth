package services_test

import (
	"os"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewUserService(t *testing.T) {
	t.Run("returns a new UserService instance", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)
		assert.NotNil(t, service)
	})
}

func TestAccountService_RegisterUser(t *testing.T) {

	user_password := "testpassword"

	userData := &entities.Account{
		Username: "testuser",
		Password: user_password,
		Email:    "mail@email.com",
	}

	t.Run("returns user with userid if data is valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(nil)

		// Test successful registration
		user, err := service.RegisterUser(userData)
		assert.NoError(t, err)
		assert.Equal(t, userData, user)

		assert.NotEmpty(t, user.ID)
		// Test salt is generated
		assert.NotEmpty(t, user.Salt)
		// Test password is hashed
		assert.NotEqual(t, user_password, userData.Password)
		// Test timestamps are generated
		assert.NotEmpty(t, user.CreatedAt)
		assert.NotEmpty(t, user.UpdatedAt)
	})

	t.Run("returns error if storage failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		// Test invalid registration
		user, err := service.RegisterUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, user)
	})

	t.Run("returns error if user exists", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBDuplicateEntry)

		// Test invalid registration
		user, err := service.RegisterUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBDuplicateEntry)
		assert.Nil(t, user)
	})

}

func TestAccountService_LoginSessionUser(t *testing.T) {

	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)

	storedData := &entities.Account{
		ID:        user_id,
		Username:  "testuser",
		Password:  hashedPassword,
		Email:     user_email,
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("valid username and password returns session data", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Username: user_name,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByUsername", user_name)
		mockStore.AssertNotCalled(t, "GetUserByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, userSession.UserID)
		assert.NotEmpty(t, userSession.SessionID)
		assert.NotEmpty(t, userSession.CreatedAt)
		assert.NotEmpty(t, userSession.UpdatedAt)
		assert.True(t, userSession.Valid)
	})

	t.Run("valid email and password returns session data", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, userSession.UserID)
		assert.NotEmpty(t, userSession.SessionID)
		assert.NotEmpty(t, userSession.CreatedAt)
		assert.NotEmpty(t, userSession.UpdatedAt)
		assert.True(t, userSession.Valid)
	})

	t.Run("returns error if password is incorrect", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: "wrongpassword",
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
		assert.Nil(t, userSession)
	})

	t.Run("returns retrieve data error if account retrieving failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrDBStorageFailed)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, userSession)
	})

	t.Run("returns store data error if session store failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, userSession)
	})

	t.Run("returns invalid credential error if entry is not found", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrDBEntryNotFound)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSession(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
		assert.Nil(t, userSession)
	})

}

func setupKeysDir() (string, string) {
	privateKeyPEM, publicKeyPEM, err := mocks.GenerateKeyPair()
	if err != nil {
		return "", ""
	}

	os.Setenv("JWT_EDCA_PRIVATE_KEY", string(privateKeyPEM))
	os.Setenv("JWT_EDCA_PUBLIC_KEY", string(publicKeyPEM))
	infra.LoadConfigFromEnv()

	return string(privateKeyPEM), string(publicKeyPEM)
}

func tearDownKeysDir() {
	os.Unsetenv("JWT_EDCA_PRIVATE_KEY")
	os.Unsetenv("JWT_EDCA_PUBLIC_KEY")
}

func TestAccountService_LoginSessionUserToken(t *testing.T) {

	_, publicKey := setupKeysDir()
	defer tearDownKeysDir()

	assert.NotEmpty(t, publicKey)

	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)

	storedData := &entities.Account{
		ID:        user_id,
		Username:  "testuser",
		Password:  hashedPassword,
		Email:     user_email,
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	testJwtClaims := func(userToken string) {
		// check jwt token
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(userToken, claims, func(token *jwt.Token) (interface{}, error) {
			key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
			return key, err
		})

		assert.NoError(t, err)
		assert.True(t, token.Valid)
		assert.NotNil(t, claims["iat"])
		assert.NotNil(t, claims["session_id"])
		assert.Equal(t, claims["user_id"], user_id.String())
		assert.NotNil(t, claims["sub"])
		assert.NotNil(t, claims["exp"])
	}

	t.Run("valid username and password returns token with userid and session id", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUsername", user_name).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Username: user_name,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "SaveSession", mock.Anything)
		mockStore.AssertCalled(t, "GetUserByUsername", user_name)
		mockStore.AssertNotCalled(t, "GetUserByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.NotEmpty(t, userToken)

		if userToken != "" {
			testJwtClaims(userToken)
		}

	})

	t.Run("valid email and password returns token with userid and session id", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", user_email).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "SaveSession", mock.Anything)
		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.NoError(t, err)
		assert.NotEmpty(t, userToken)

		if userToken != "" {
			testJwtClaims(userToken)
		}
	})

	t.Run("returns error if password is incorrect", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", user_email).Return(storedData, nil)

		requestData := &entities.Account{
			Email:    user_email,
			Password: "wrongpassword",
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
		assert.Empty(t, userToken)
	})

	t.Run("returns retrieve data error if account retrieving failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", user_email).Return(nil, svrerr.ErrDBStorageFailed)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Empty(t, userToken)
	})

	t.Run("returns storage error if session store failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", user_email).Return(storedData, nil)
		mockStore.On("SaveSession", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userSession, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertCalled(t, "SaveSession", mock.Anything)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Empty(t, userSession)
	})

	t.Run("returns invalid credential error if user entry not found", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", user_email).Return(nil, svrerr.ErrDBEntryNotFound)

		requestData := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}
		userToken, err := service.LoginUserSessionToken(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)
		mockStore.AssertNotCalled(t, "SaveSession", mock.Anything)

		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
		assert.Empty(t, userToken)
	})
}

func TestAccountService_GetUserBySessionID(t *testing.T) {
	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	// user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	// salt, _ := utils.GenerateSalt()
	// hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)
	session_id := uuid.NewString()

	storedData := &entities.Account{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns user data if session id is valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(storedData, nil)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.NoError(t, err)
		assert.Equal(t, storedData, userData)
	})

	t.Run("returns error if session id is invalid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(nil, svrerr.ErrDBEntryNotFound)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
		assert.Empty(t, userData)
	})

	t.Run("returns error if storage fails to retrieve", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(nil, svrerr.ErrDBStorageFailed)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Empty(t, userData)
	})
}

func generateToken(user, session string) (string, error) {
	claims := helpers.MakeCustomClaims(user, session)
	return helpers.GetSignedTokenWithClaims(claims)
}

func generateExpiredToken(user, session string) (string, error) {

	type customClaims struct {
		SessionID string `json:"session_id"`
		UserID    string `json:"user_id"`
		jwt.RegisteredClaims
	}

	timeNow := time.Now().Add(-time.Hour)

	claims := customClaims{
		SessionID: session,
		UserID:    user,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "authentication",
			Issuer:    "stk-auth",
			Audience:  jwt.ClaimStrings{"stk"},
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(timeNow.Add(1 * time.Second)),
		},
	}

	token, err := helpers.GetSignedTokenWithClaims(claims)
	return token, err
}

func TestAccountService_GetUserBySessionToken(t *testing.T) {

	setupKeysDir()
	defer tearDownKeysDir()

	user_name := "testuser"
	user_email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	user_id := entities.UserID(uuid.New())
	session_id := uuid.NewString()

	token, err := generateToken(user_id.String(), session_id)
	assert.NoError(t, err)

	expired_token, err := generateExpiredToken(user_id.String(), session_id)
	assert.NoError(t, err)

	invalid_token := "invalid_token"

	storedData := &entities.Account{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	accountWithToken := &entities.AccountWithToken{
		Account: *storedData,
		Token:   "",
	}

	t.Run("returns user data if session token is valid and not expired", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUserID", user_id.String()).Return(storedData, nil)

		userData, err := service.GetUserBySessionToken(token)

		mockStore.AssertCalled(t, "GetUserByUserID", user_id.String())
		mockStore.AssertNotCalled(t, "GetUserBySessionID", user_id.String())

		assert.NoError(t, err)
		assert.Equal(t, accountWithToken.Account, userData.Account)
		assert.NotEmpty(t, userData.Token)
		assert.Equal(t, token, userData.Token)

	})

	t.Run("returns user data and updated token if session token is valid but expired", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(storedData, nil)

		userData, err := service.GetUserBySessionToken(expired_token)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)
		mockStore.AssertNotCalled(t, "GetUserByUserID", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, accountWithToken.Account, userData.Account)
		assert.NotEmpty(t, userData.Token)
		assert.NotEqual(t, expired_token, userData.Token)
	})

	t.Run("returns error if session token is invalid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		userData, err := service.GetUserBySessionToken(invalid_token)

		mockStore.AssertNotCalled(t, "GetUserByUserID", mock.Anything)

		assert.ErrorIs(t, err, svrerr.ErrInvalidToken)
		assert.Empty(t, userData)
	})

}

func TestAccountService_LogoutUserBySessionId(t *testing.T) {

	session_id := uuid.NewString()

	t.Run("returns no error if session is invalidated", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(nil)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.NoError(t, err)
	})

	t.Run("returns error if session is not invalidated", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBStorageFailed)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
	t.Run("returns error if session is invalid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBEntryNotFound)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
}

func TestAccountService_LogoutUserBySessionToken(t *testing.T) {
	_, _ = setupKeysDir()
	defer tearDownKeysDir()

	user_id := entities.UserID(uuid.New())
	session_id := uuid.NewString()

	token, err := generateToken(user_id.String(), session_id)
	assert.NoError(t, err)

	expired_token, err := generateExpiredToken(user_id.String(), session_id)
	assert.NoError(t, err)

	t.Run("returns no error with valid token and session id", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(nil)

		err := service.LogoutUserBySessionToken(token)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.NoError(t, err)
	})

	t.Run("returns no error if token is expired", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(nil)

		err := service.LogoutUserBySessionToken(expired_token)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.NoError(t, err)
	})

	t.Run("returns error if session is not invalidated", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBStorageFailed)

		err := service.LogoutUserBySessionToken(token)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
	t.Run("returns error if session is invalid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBEntryNotFound)

		err := service.LogoutUserBySessionToken(token)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
}
