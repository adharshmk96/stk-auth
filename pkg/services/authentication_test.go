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

func TestAuthenticationService_CreateAccount(t *testing.T) {

	account_password := "testpassword"

	accountData := &ds.Account{
		Username: "testaccount",
		Password: account_password,
		Email:    "mail@email.com",
	}

	t.Run("returns account with accountid if data is valid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveAccount", mock.Anything).Return(nil)

		// Test successful registration
		account, err := service.CreateAccount(accountData)
		assert.NoError(t, err)
		assert.Equal(t, accountData, account)

		assert.NotEmpty(t, account.ID)
		// Test salt is generated
		assert.NotEmpty(t, account.Salt)
		// Test password is hashed
		assert.NotEqual(t, account_password, accountData.Password)
		// Test timestamps are generated
		assert.NotEmpty(t, account.CreatedAt)
		assert.NotEmpty(t, account.UpdatedAt)
	})

	t.Run("returns error if email is empty", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		newAccountData := &ds.Account{
			Username: "testaccount",
			Password: account_password,
		}

		// Test invalid registration
		account, err := service.CreateAccount(newAccountData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrValidationFailed)
		assert.Nil(t, account)
	})

	t.Run("returns error if storage failed", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveAccount", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		// Test invalid registration
		account, err := service.CreateAccount(accountData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, account)
	})

	t.Run("returns error if account exists", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveAccount", mock.Anything).Return(svrerr.ErrDBDuplicateEntry)

		// Test invalid registration
		account, err := service.CreateAccount(accountData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBDuplicateEntry)
		assert.Nil(t, account)
	})
}

func TestAuthenticationService_Authenticate(t *testing.T) {

	account_id := ds.AccountID(uuid.New())
	account_name := "testaccount"
	account_email := "account@email.com"
	account_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(account_password, salt)

	storedData := &ds.Account{
		ID:        account_id,
		Username:  "testaccount",
		Password:  hashedPassword,
		Email:     account_email,
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("valid username and password returns no error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByUsername", mock.Anything).Return(storedData, nil)

		account := &ds.Account{
			Username: account_name,
			Password: account_password,
		}

		err := service.Authenticate(account)

		mockStore.AssertCalled(t, "GetAccountByUsername", account_name)
		mockStore.AssertNotCalled(t, "GetAccountByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, account.ID)
		assert.Equal(t, storedData.Username, account.Username)
		assert.Equal(t, storedData.Email, account.Email)
		assert.Equal(t, storedData.CreatedAt, account.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, account.UpdatedAt)
	})

	t.Run("valid email and password returns no error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByEmail", mock.Anything).Return(storedData, nil)

		account := &ds.Account{
			Email:    account_email,
			Password: account_password,
		}

		err := service.Authenticate(account)

		mockStore.AssertCalled(t, "GetAccountByEmail", account_email)
		mockStore.AssertNotCalled(t, "GetAccountByUsername", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, account.ID)
		assert.Equal(t, storedData.Username, account.Username)
		assert.Equal(t, storedData.Email, account.Email)
		assert.Equal(t, storedData.CreatedAt, account.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, account.UpdatedAt)
	})

	t.Run("invalid username and password returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByUsername", mock.Anything).Return(nil, svrerr.ErrDBEntryNotFound)

		account := &ds.Account{
			Username: account_name,
			Password: account_password,
		}

		err := service.Authenticate(account)

		mockStore.AssertCalled(t, "GetAccountByUsername", account_name)
		mockStore.AssertNotCalled(t, "GetAccountByEmail", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
	})

	t.Run("email and wrong password returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByEmail", mock.Anything).Return(storedData, nil)

		account := &ds.Account{
			Email:    account_email,
			Password: "wrongpassword",
		}

		err := service.Authenticate(account)

		mockStore.AssertCalled(t, "GetAccountByEmail", account_email)
		mockStore.AssertNotCalled(t, "GetAccountByUsername", mock.Anything)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrInvalidCredentials)
	})
}

func TestAuthenticationService_GetAccountByID(t *testing.T) {
	account_id := ds.AccountID(uuid.New())
	account_name := "testaccount"
	account_email := "account@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &ds.Account{
		ID:        account_id,
		Username:  account_name,
		Email:     account_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("valid account id returns account data", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByAccountID", account_id.String()).Return(storedData, nil).Once()

		account, err := service.GetAccountByID(account_id.String())

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), account.ID.String())
		assert.Equal(t, storedData.Username, account.Username)
		assert.Equal(t, storedData.Email, account.Email)
		assert.Equal(t, storedData.CreatedAt, account.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, account.UpdatedAt)
	})

	t.Run("invalid account id returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountByAccountID", account_id.String()).Return(nil, svrerr.ErrDBEntryNotFound)

		account, err := service.GetAccountByID(account_id.String())

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBEntryNotFound)
		assert.Nil(t, account)
	})
}
func TestAuthenticationService_ChangePassword(t *testing.T) {

	email := "account@email.com"
	new_password := "new_password"
	lastHour := time.Now().Add(-1 * time.Hour)
	created_at := lastHour
	updated_at := lastHour

	inputAccount := &ds.Account{
		Email:     email,
		Password:  new_password,
		CreatedAt: created_at,
		UpdatedAt: updated_at,
	}

	t.Run("returns no error if password is changed", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("UpdateAccountByID", inputAccount).Return(nil).Once()

		err := service.ChangePassword(inputAccount)

		assert.NoError(t, err)
		assert.NotEqual(t, inputAccount.Password, new_password)
		assert.NotEqual(t, inputAccount.UpdatedAt.Unix(), lastHour.Unix())
		assert.Equal(t, inputAccount.CreatedAt.Unix(), lastHour.Unix())
	})

	t.Run("returns error if password is not changed", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("UpdateAccountByID", inputAccount).Return(svrerr.ErrDBStorageFailed).Once()

		err := service.ChangePassword(inputAccount)

		assert.Error(t, err)
	})
}

func TestAuthenticationService_CreateSession(t *testing.T) {

	account_name := "testaccount"

	t.Run("valid username and password returns session data", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveSession", mock.AnythingOfType("*ds.Session")).Return(nil).Once()

		requestData := &ds.Account{
			ID:       ds.AccountID(uuid.New()),
			Username: account_name,
		}
		accountSession, err := service.CreateSession(requestData)

		mockStore.AssertExpectations(t)

		assert.NoError(t, err)
		assert.NotEmpty(t, accountSession.SessionID)
		assert.NotEmpty(t, accountSession.CreatedAt)
		assert.NotEmpty(t, accountSession.UpdatedAt)
		assert.True(t, accountSession.Valid)
	})

	t.Run("returns store data error if session store failed", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SaveSession", mock.AnythingOfType("*ds.Session")).Return(svrerr.ErrDBStorageFailed).Once()

		requestData := &ds.Account{
			ID:       ds.AccountID(uuid.New()),
			Username: account_name,
		}
		accountSession, err := service.CreateSession(requestData)

		mockStore.AssertExpectations(t)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, accountSession)
	})

	t.Run("returns error for empty accountdata", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		requestData := &ds.Account{}

		accountSession, err := service.CreateSession(requestData)

		assert.Error(t, err)
		assert.Nil(t, accountSession)
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

func TestAuthenticationService_LogoutAccountBySessionId(t *testing.T) {

	session_id := uuid.NewString()

	t.Run("returns no error if session is invalidated", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(nil)

		err := service.LogoutAccountBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.NoError(t, err)
	})

	t.Run("returns error if session is not invalidated", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBStorageFailed)

		err := service.LogoutAccountBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
	t.Run("returns error if session is invalid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBEntryNotFound)

		err := service.LogoutAccountBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
}

func TestAuthenticationService_GetAccountBySessionID(t *testing.T) {
	account_id := ds.AccountID(uuid.New())
	account_name := "testaccount"
	account_email := "account@email.com"
	// account_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	// salt, _ := utils.GenerateSalt()
	// hashedPassword, hashedSalt := utils.HashPassword(account_password, salt)
	session_id := uuid.NewString()

	storedData := &ds.Account{
		ID:        account_id,
		Username:  account_name,
		Email:     account_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns account data if session id is valid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountBySessionID", session_id).Return(storedData, nil)

		accountData, err := service.GetAccountBySessionId(session_id)

		mockStore.AssertCalled(t, "GetAccountBySessionID", session_id)

		assert.NoError(t, err)
		assert.Equal(t, storedData, accountData)
	})

	t.Run("returns error if session id is invalid", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountBySessionID", session_id).Return(nil, svrerr.ErrDBEntryNotFound)

		accountData, err := service.GetAccountBySessionId(session_id)

		mockStore.AssertCalled(t, "GetAccountBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
		assert.Empty(t, accountData)
	})

	t.Run("returns error if storage fails to retrieve", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("GetAccountBySessionID", session_id).Return(nil, svrerr.ErrDBStorageFailed)

		accountData, err := service.GetAccountBySessionId(session_id)

		mockStore.AssertCalled(t, "GetAccountBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Empty(t, accountData)
	})
}

func TestAuthenticationService_GenerateJWT(t *testing.T) {

	t.Run("generates a valid token", func(t *testing.T) {
		setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		accountId := uuid.NewString()

		claims := &entities.CustomClaims{
			AccountID: accountId,
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

		assert.Equal(t, accountId, parsedClaims.AccountID)
	})

	t.Run("returns error if key is invalid", func(t *testing.T) {
		viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY, "")
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		accountId := uuid.NewString()

		claims := &entities.CustomClaims{
			AccountID: accountId,
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

		accountId := uuid.NewString()

		claims := &entities.CustomClaims{
			AccountID: accountId,
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

		assert.Equal(t, accountId, validatedClaims.AccountID)
	})

	t.Run("returns error if token is invalid", func(t *testing.T) {
		setupKeysDir()

		infra.LoadDefaultConfig()
		viper.AutomaticEnv()

		dbStorage := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(dbStorage)

		accountId := uuid.NewString()

		claims := &entities.CustomClaims{
			AccountID: accountId,
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

func TestAuthenticationService_SendPasswordResetEmail(t *testing.T) {

	t.Run("returns no error if email is sent", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		mockStore.On("SavePasswordResetToken", mock.AnythingOfType("*ds.PasswordResetToken")).Return(nil).Once()

		email := "user@email.com"

		err := service.SendPasswordResetEmail(email)

		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})
}

func TestAuthenticationService_ResetPassword(t *testing.T) {
	t.Run("returns no error if password is reset", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAuthenticationService(mockStore)

		token := uuid.NewString()
		password := "newpassword"

		mockStore.On("UpdateAccountByID", mock.AnythingOfType("*ds.Account")).Return(nil).Once()
		mockStore.On("InvalidateResetToken", token).Return(nil).Once()

		err := service.ResetPassword(token, password)

		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})
}
