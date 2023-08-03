package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk-auth/testHelpers"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewAuthenticationService(t *testing.T) {
	t.Run("returns a new AuthenticationService instance", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)
		assert.NotNil(t, service)
	})
}

func TestAuthenticationService_CreateUser(t *testing.T) {

	user_password := "testpassword"

	userData := &ds.Account{
		Username: "testuser",
		Password: user_password,
		Email:    "mail@email.com",
	}

	t.Run("returns user with userid if data is valid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

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
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		newUserData := &ds.Account{
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
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		// Test invalid registration
		user, err := service.CreateUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, user)
	})

	t.Run("returns error if user exists", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBDuplicateEntry)

		// Test invalid registration
		user, err := service.CreateUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBDuplicateEntry)
		assert.Nil(t, user)
	})
}

func TestAuthenticationService_Authenticate(t *testing.T) {

	user_id := ds.AccountID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)

	storedData := &ds.Account{
		ID:        user_id,
		Username:  "testuser",
		Password:  hashedPassword,
		Email:     user_email,
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("valid username and password returns no error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(storedData, nil)

		user := &ds.Account{
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
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		user := &ds.Account{
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
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserByUsername", mock.Anything).Return(nil, svrerr.ErrDBEntryNotFound)

		user := &ds.Account{
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
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		user := &ds.Account{
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

func TestAuthenticationService_GetUserByID(t *testing.T) {
	user_id := ds.AccountID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &ds.Account{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("valid user id returns user data", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserByUserID", user_id.String()).Return(storedData, nil).Once()

		user, err := service.GetUserByID(user_id.String())

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), user.ID.String())
		assert.Equal(t, storedData.Username, user.Username)
		assert.Equal(t, storedData.Email, user.Email)
		assert.Equal(t, storedData.CreatedAt, user.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, user.UpdatedAt)
	})

	t.Run("invalid user id returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserByUserID", user_id.String()).Return(nil, svrerr.ErrDBEntryNotFound)

		user, err := service.GetUserByID(user_id.String())

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBEntryNotFound)
		assert.Nil(t, user)
	})
}
func TestAuthenticationService_ChangePassword(t *testing.T) {

	email := "user@email.com"
	new_password := "new_password"
	lastHour := time.Now().Add(-1 * time.Hour)
	created_at := lastHour
	updated_at := lastHour

	inputUser := &ds.Account{
		Email:     email,
		Password:  new_password,
		CreatedAt: created_at,
		UpdatedAt: updated_at,
	}

	t.Run("returns no error if password is changed", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("UpdateUserByID", inputUser).Return(nil).Once()

		err := service.ChangePassword(inputUser)

		assert.NoError(t, err)
		assert.NotEqual(t, inputUser.Password, new_password)
		assert.NotEqual(t, inputUser.UpdatedAt.Unix(), lastHour.Unix())
		assert.Equal(t, inputUser.CreatedAt.Unix(), lastHour.Unix())
	})

	t.Run("returns error if password is not changed", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("UpdateUserByID", inputUser).Return(svrerr.ErrDBStorageFailed).Once()

		err := service.ChangePassword(inputUser)

		assert.Error(t, err)
	})
}

func TestAuthenticationService_CreateSession(t *testing.T) {

	user_name := "testuser"

	t.Run("valid username and password returns session data", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveSession", mock.AnythingOfType("*ds.Session")).Return(nil).Once()

		requestData := &ds.Account{
			ID:       ds.AccountID(uuid.New()),
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
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveSession", mock.AnythingOfType("*ds.Session")).Return(svrerr.ErrDBStorageFailed).Once()

		requestData := &ds.Account{
			ID:       ds.AccountID(uuid.New()),
			Username: user_name,
		}
		userSession, err := service.CreateSession(requestData)

		mockStore.AssertExpectations(t)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, userSession)
	})

	t.Run("returns error for empty userdata", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		requestData := &ds.Account{}

		userSession, err := service.CreateSession(requestData)

		assert.Error(t, err)
		assert.Nil(t, userSession)
	})
}

func setupKeysDir() (string, string) {
	privateKeyPEM, publicKeyPEM, err := testHelpers.GenerateKeyPair()
	if err != nil {
		return "", ""
	}

	viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, string(privateKeyPEM))
	viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY, string(publicKeyPEM))

	return string(privateKeyPEM), string(publicKeyPEM)
}

func TestAuthenticationService_LogoutUserBySessionId(t *testing.T) {

	session_id := uuid.NewString()

	t.Run("returns no error if session is invalidated", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(nil)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.NoError(t, err)
	})

	t.Run("returns error if session is not invalidated", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBStorageFailed)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
	t.Run("returns error if session is invalid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBEntryNotFound)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
}

func TestAuthenticationService_GetUserBySessionID(t *testing.T) {
	user_id := ds.AccountID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	// user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	// salt, _ := utils.GenerateSalt()
	// hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)
	session_id := uuid.NewString()

	storedData := &ds.Account{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns user data if session id is valid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(storedData, nil)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.NoError(t, err)
		assert.Equal(t, storedData, userData)
	})

	t.Run("returns error if session id is invalid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(nil, svrerr.ErrDBEntryNotFound)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
		assert.Empty(t, userData)
	})

	t.Run("returns error if storage fails to retrieve", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(nil, svrerr.ErrDBStorageFailed)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Empty(t, userData)
	})
}

func TestAuthenticationService_GenerateJWT(t *testing.T) {

	t.Run("generates a valid token", func(t *testing.T) {
		setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
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
	})

	t.Run("returns error if key is invalid", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "")
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
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

func TestAuthenticationService_ValidateJWT(t *testing.T) {

	t.Run("returns no error if token is valid", func(t *testing.T) {
		setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
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
		setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		userId := uuid.NewString()

		claims := &entities.CustomClaims{
			UserID: userId,
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
