package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
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

	viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, string(privateKeyPEM))
	viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY, string(publicKeyPEM))

	return string(privateKeyPEM), string(publicKeyPEM)
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
	infra.LoadDefaultConfig()

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

func parseToken(token string) (*entities.CustomClaims, error) {

	claims := entities.CustomClaims{}

	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(viper.GetString(constants.ENV_JWT_EDCA_PUBLIC_KEY)))
	})
	return &claims, err
}

func TestAccountService_TestGenerateJWT(t *testing.T) {

	t.Run("generates a valid token", func(t *testing.T) {
		_, _ = setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAccountStore(t)
		service := services.NewAccountService(dbStorage)

		user := &entities.Account{
			ID:       entities.UserID(uuid.New()),
			Username: "test",
			Password: "test",
		}

		session := &entities.Session{
			SessionID: uuid.NewString(),
			UserID:    user.ID,
		}

		token, err := service.GenerateJWT(user, session)
		assert.NoError(t, err)

		claims, _ := parseToken(token)
		assert.NoError(t, err)

		assert.Equal(t, user.ID.String(), claims.UserID)
		assert.Equal(t, session.SessionID, claims.SessionID)
	})

	t.Run("returns error if key is invalid", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "")
		viper.AutomaticEnv()

		dbStorage := mocks.NewAccountStore(t)
		service := services.NewAccountService(dbStorage)

		user := &entities.Account{
			ID:       entities.UserID(uuid.New()),
			Username: "test",
			Password: "test",
		}

		session := &entities.Session{
			SessionID: uuid.NewString(),
			UserID:    user.ID,
		}

		token, err := service.GenerateJWT(user, session)
		assert.Error(t, err)

		assert.Empty(t, token)

	})
}
