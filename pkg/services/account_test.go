package services_test

import (
	"testing"

	"github.com/adharshmk96/auth-server/mocks"
	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
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

}

func TestAccountService_GetUserByID(t *testing.T) {

	user := &entities.Account{
		ID:       entities.UserID(uuid.New()),
		Username: "testuser",
		Email:    "testemail",
	}

	t.Run("returns user if user exists", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByID", mock.Anything).Return(user, nil)

		retrievedUser, err := service.GetUserByID(user.ID)

		assert.NoError(t, err)
		assert.NotNil(t, retrievedUser)
		assert.Equal(t, user, retrievedUser)
	})

	t.Run("returns err if user doesnt exist", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByID", mock.Anything).Return(nil, svrerr.ErrNoAccountFound)

		retrievedUser, err := service.GetUserByID(entities.UserID(uuid.New()))

		assert.Error(t, err)
		assert.Nil(t, retrievedUser)
		assert.EqualError(t, err, svrerr.ErrNoAccountFound.Error())
	})

	t.Run("returns err if storage failed", func(t *testing.T) {
		mockStore := mocks.NewAccountStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByID", mock.Anything).Return(nil, svrerr.ErrRetrievingAccount)

		// Test invalid retrieval
		user, err := service.GetUserByID(entities.UserID(uuid.New()))
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrRetrievingAccount.Error())
		assert.Nil(t, user)
	})
}
