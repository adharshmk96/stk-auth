package services_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAdminService_GetUserList(t *testing.T) {
	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &entities.User{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns user list defaults 10 if limit is 0", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetUserList", 10, 0).Return([]*entities.User{storedData}, nil).Once()

		user, err := service.GetUserList(0, 0)

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), user[0].ID.String())
		assert.Equal(t, storedData.Username, user[0].Username)
		assert.Equal(t, storedData.Email, user[0].Email)
		assert.Equal(t, storedData.CreatedAt, user[0].CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, user[0].UpdatedAt)
	})

	t.Run("storage error returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetUserList", 10, 0).Return(nil, svrerr.ErrDBStorageFailed).Once()

		user, err := service.GetUserList(0, 0)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, user)
	})

	t.Run("returns user list with limit and offset", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetUserList", 10, 10).Return([]*entities.User{storedData}, nil).Once()

		user, err := service.GetUserList(10, 10)

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), user[0].ID.String())
		assert.Equal(t, storedData.Username, user[0].Username)
		assert.Equal(t, storedData.Email, user[0].Email)
		assert.Equal(t, storedData.CreatedAt, user[0].CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, user[0].UpdatedAt)
	})
}

func TestAdminService_GetTotalUsersCount(t *testing.T) {
	t.Run("returns total user count", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetTotalUsersCount").Return(int64(10), nil).Once()

		count, err := service.GetTotalUsersCount()

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, int64(10), count)
	})

	t.Run("storage error returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetTotalUsersCount").Return(int64(0), svrerr.ErrDBStorageFailed).Once()

		count, err := service.GetTotalUsersCount()

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Equal(t, int64(0), count)
	})
}

func TestAdminService_GetUserDetails(t *testing.T) {
	user_id := entities.UserID(uuid.New())
	user_name := "testuser"
	user_email := "user@email.com"
	created := time.Now()
	updated := time.Now()

	storedData := &entities.User{
		ID:        user_id,
		Username:  user_name,
		Email:     user_email,
		CreatedAt: created,
		UpdatedAt: updated,
	}

	t.Run("returns user details", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetUserByUserID", user_id.String()).Return(storedData, nil).Once()

		user, err := service.GetUserDetails(user_id)

		mockStore.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, storedData.ID.String(), user.ID.String())
		assert.Equal(t, storedData.Username, user.Username)
		assert.Equal(t, storedData.Email, user.Email)
		assert.Equal(t, storedData.CreatedAt, user.CreatedAt)
		assert.Equal(t, storedData.UpdatedAt, user.UpdatedAt)
	})

	t.Run("storage error returns error", func(t *testing.T) {
		mockStore := mocks.NewAuthenticationStore(t)
		service := services.NewAdminService(mockStore)

		mockStore.On("GetUserByUserID", user_id.String()).Return(nil, svrerr.ErrDBStorageFailed).Once()

		user, err := service.GetUserDetails(user_id)

		assert.Error(t, err)
		assert.ErrorIs(t, err, svrerr.ErrDBStorageFailed)
		assert.Nil(t, user)
	})
}
