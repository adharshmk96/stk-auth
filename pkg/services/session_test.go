package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewUserService(t *testing.T) {
	t.Run("returns a new UserService instance", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)
		assert.NotNil(t, service)
	})
}

func TestAccountService_CreateSession(t *testing.T) {

	user_name := "testuser"

	t.Run("valid username and password returns session data", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

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
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

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
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

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

func TestAccountService_LogoutUserBySessionId(t *testing.T) {

	session_id := uuid.NewString()

	t.Run("returns no error if session is invalidated", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(nil)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.NoError(t, err)
	})

	t.Run("returns error if session is not invalidated", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBStorageFailed)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
	})
	t.Run("returns error if session is invalid", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

		mockStore.On("InvalidateSessionByID", session_id).Return(svrerr.ErrDBEntryNotFound)

		err := service.LogoutUserBySessionId(session_id)

		mockStore.AssertCalled(t, "InvalidateSessionByID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
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
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(storedData, nil)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.NoError(t, err)
		assert.Equal(t, storedData, userData)
	})

	t.Run("returns error if session id is invalid", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(nil, svrerr.ErrDBEntryNotFound)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrInvalidSession)
		assert.Empty(t, userData)
	})

	t.Run("returns error if storage fails to retrieve", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewUserManagementService(mockStore)

		mockStore.On("GetUserBySessionID", session_id).Return(nil, svrerr.ErrDBStorageFailed)

		userData, err := service.GetUserBySessionId(session_id)

		mockStore.AssertCalled(t, "GetUserBySessionID", session_id)

		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Empty(t, userData)
	})
}
