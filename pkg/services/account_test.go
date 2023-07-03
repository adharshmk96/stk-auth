package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/services"
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

func TestAccountService_CreateUser(t *testing.T) {

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
		user, err := service.CreateUser(userData)
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

	t.Run("returns error if email is empty", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		newUserData := &entities.Account{
			Username: "testuser",
			Password: user_password,
		}

		// Test invalid registration
		user, err := service.CreateUser(newUserData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrValidationFailed)
		assert.Nil(t, user)
	})

	t.Run("returns error if storage failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		// Test invalid registration
		user, err := service.CreateUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, user)
	})

	t.Run("returns error if user exists", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBDuplicateEntry)

		// Test invalid registration
		user, err := service.CreateUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBDuplicateEntry)
		assert.Nil(t, user)
	})

}

func TestAccountService_Authenticate(t *testing.T) {

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

	t.Run("valid username and password returns no error", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(storedData, nil)

		user := &entities.Account{
			Username: user_name,
			Password: user_password,
		}

		err := service.Authenticate(user)

		mockStore.AssertCalled(t, "GetUserByUsername", user_name)
		mockStore.AssertNotCalled(t, "GetUserByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, user.ID)
		assert.Equal(t, storedData.Username, user.Username)
		assert.Equal(t, storedData.Email, user.Email)
		assert.Equal(t, storedData.CreatedAt, user.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, user.UpdatedAt)
	})

	t.Run("valid email and password returns no error", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		user := &entities.Account{
			Email:    user_email,
			Password: user_password,
		}

		err := service.Authenticate(user)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, user.ID)
		assert.Equal(t, storedData.Username, user.Username)
		assert.Equal(t, storedData.Email, user.Email)
		assert.Equal(t, storedData.CreatedAt, user.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, user.UpdatedAt)
	})

	t.Run("invalid username and password returns error", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(nil, svrerr.ErrDBEntryNotFound)

		user := &entities.Account{
			Username: user_name,
			Password: user_password,
		}

		err := service.Authenticate(user)

		mockStore.AssertCalled(t, "GetUserByUsername", user_name)
		mockStore.AssertNotCalled(t, "GetUserByEmail", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
	})

	t.Run("email and wrong password returns error", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		user := &entities.Account{
			Email:    user_email,
			Password: "wrongpassword",
		}

		err := service.Authenticate(user)

		mockStore.AssertCalled(t, "GetUserByEmail", user_email)
		mockStore.AssertNotCalled(t, "GetUserByUsername", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
	})
}

func TestAccountService_CreateSession(t *testing.T) {

	user_name := "testuser"

	t.Run("valid username and password returns session data", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveSession", mock.AnythingOfType("*entities.Session")).Return(nil).Once()

		requestData := &entities.Account{
			ID:       entities.UserID(uuid.New()),
			Username: user_name,
		}
		userSession, err := service.CreateSession(requestData)

		mockStore.AssertExpectations(t)

		assert.NoError(t, err)
		assert.NotEmpty(t, userSession.SessionID)
		assert.NotEmpty(t, userSession.CreatedAt)
		assert.NotEmpty(t, userSession.UpdatedAt)
		assert.True(t, userSession.Valid)
	})

	t.Run("returns store data error if session store failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveSession", mock.AnythingOfType("*entities.Session")).Return(svrerr.ErrDBStorageFailed).Once()

		requestData := &entities.Account{
			ID:       entities.UserID(uuid.New()),
			Username: user_name,
		}
		userSession, err := service.CreateSession(requestData)

		mockStore.AssertExpectations(t)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, userSession)
	})

	t.Run("returns error for empty userdata", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		requestData := &entities.Account{}

		userSession, err := service.CreateSession(requestData)

		assert.Error(t, err)
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

		userId := uuid.NewString()
		sessionId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID:    userId,
			SessionID: sessionId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.NoError(t, err)

		parsedClaims, _ := parseToken(token)
		assert.NoError(t, err)

		assert.Equal(t, userId, parsedClaims.UserID)
		assert.Equal(t, sessionId, parsedClaims.SessionID)
	})

	t.Run("returns error if key is invalid", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "")
		viper.AutomaticEnv()

		dbStorage := mocks.NewAccountStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()
		sessionId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID:    userId,
			SessionID: sessionId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.Error(t, err)

		assert.Empty(t, token)

	})
}

func TestAccountService_ValidateJWT(t *testing.T) {

	t.Run("returns no error if token is valid", func(t *testing.T) {
		_, _ = setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAccountStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()
		sessionId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID:    userId,
			SessionID: sessionId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.NoError(t, err)

		validatedClaims, err := service.ValidateJWT(token)
		assert.NoError(t, err)

		assert.Equal(t, userId, validatedClaims.UserID)
	})

	t.Run("returns error if token is invalid", func(t *testing.T) {
		_, _ = setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAccountStore(t)
		service := services.NewAccountService(dbStorage)

		userId := uuid.NewString()
		sessionId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID:    userId,
			SessionID: sessionId,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Issuer:    viper.GetString(constants.ENV_JWT_ISSUER),
				Subject:   viper.GetString(constants.ENV_JWT_SUBJECT),
			},
		}

		token, err := service.GenerateJWT(claims)
		assert.NoError(t, err)

		invalidToken := token + "invalid"

		_, err = service.ValidateJWT(invalidToken)
		assert.Error(t, err)

	})

}
