package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAccountService_CreateUser(t *testing.T) {

	user_password := "testpassword"

	userData := &entities.Account{
		Username: "testuser",
		Password: user_password,
		Email:    "mail@email.com",
	}

	t.Run("returns user with userid if data is valid", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
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
		mockStore := mocks.NewUserManagementStore(t)
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
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("SaveUser", mock.Anything).Return(svrerr.ErrDBStorageFailed)

		// Test invalid registration
		user, err := service.CreateUser(userData)
		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, user)
	})

	t.Run("returns error if user exists", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
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
		mockStore := mocks.NewUserManagementStore(t)
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
		mockStore := mocks.NewUserManagementStore(t)
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
		mockStore := mocks.NewUserManagementStore(t)
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
		mockStore := mocks.NewUserManagementStore(t)
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

func TestAccountService_GetUserByID(t *testing.T) {
	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &entities.Account{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("valid user id returns user data", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(mockStore)

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
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("GetUserByUserID", user_id.String()).Return(nil, svrerr.ErrDBEntryNotFound)

		user, err := service.GetUserByID(user_id.String())

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBEntryNotFound)
		assert.Nil(t, user)
	})
}
func TestAccountService_ChangePassword(t *testing.T) {

	email := "user@email.com"
	new_password := "new_password"
	lastHour := time.Now().Add(-1 * time.Hour)
	created_at := lastHour
	updated_at := lastHour

	inputUser := &entities.Account{
		Email:     email,
		Password:  new_password,
		CreatedAt: created_at,
		UpdatedAt: updated_at,
	}

	t.Run("returns no error if password is changed", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("UpdateUserByID", inputUser).Return(nil).Once()

		err := service.ChangePassword(inputUser)

		assert.NoError(t, err)
		assert.NotEqual(t, inputUser.Password, new_password)
		assert.NotEqual(t, inputUser.UpdatedAt.Unix(), lastHour.Unix())
		assert.Equal(t, inputUser.CreatedAt.Unix(), lastHour.Unix())
	})

	t.Run("returns error if password is not changed", func(t *testing.T) {
		mockStore := mocks.NewUserManagementStore(t)
		service := services.NewAccountService(mockStore)

		mockStore.On("UpdateUserByID", inputUser).Return(svrerr.ErrDBStorageFailed).Once()

		err := service.ChangePassword(inputUser)

		assert.Error(t, err)
	})
}
