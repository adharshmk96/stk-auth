package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/auth-server/mocks"
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
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

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrStoringAccount)

		// Test invalid registration
		user, err := service.RegisterUser(userData)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrStoringAccount.Error())
		assert.Nil(t, user)
	})

	t.Run("returns error if user exists", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrAccountDuplicate)

		// Test invalid registration
		user, err := service.RegisterUser(userData)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrAccountDuplicate.Error())
		assert.Nil(t, user)
	})

}

func TestAccountService_LoginSessionUser(t *testing.T) {

	user_id := entities.UserID(uuid.New())
	user_password := "testpassword"
	created := time.Now()
	updated := time.Now()

	salt, _ := utils.GenerateSalt()
	hashedPassword, hashedSalt := utils.HashPassword(user_password, salt)

	requestData := &entities.Account{
		Username: "testuser",
		Password: user_password,
	}

	storedData := &entities.Account{
		ID:        user_id,
		Username:  "testuser",
		Password:  hashedPassword,
		Email:     "user@email.com",
		Salt:      hashedSalt,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns user with userid if data is valid", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		retrievedUser, err := service.LoginSessionUser(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)

		assert.NoError(t, err)
		assert.Equal(t, storedData.ID, retrievedUser.ID)
		assert.Equal(t, requestData.Username, retrievedUser.Username)
		assert.Equal(t, storedData.Password, retrievedUser.Password)
		assert.Equal(t, storedData.Salt, retrievedUser.Salt)
		assert.Equal(t, storedData.Email, retrievedUser.Email)
		assert.Equal(t, storedData.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, storedData.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("returns error if password is incorrect", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(storedData, nil)

		requestData.Password = "wrongpassword"

		retrievedUser, err := service.LoginSessionUser(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)

		assert.EqualError(t, err, svrerr.ErrInvalidCredentials.Error())
		assert.Nil(t, retrievedUser)
	})

	t.Run("returns error if storage failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrRetrievingAccount)

		retrievedUser, err := service.LoginSessionUser(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrRetrievingAccount.Error())
		assert.Nil(t, retrievedUser)
	})

	t.Run("returns error if user does not exist", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByEmail", mock.Anything).Return(nil, svrerr.ErrAccountNotFound)

		retrievedUser, err := service.LoginSessionUser(requestData)

		mockStore.AssertCalled(t, "GetUserByEmail", mock.Anything)

		assert.EqualError(t, err, svrerr.ErrInvalidCredentials.Error())
		assert.Nil(t, retrievedUser)
	})

}
