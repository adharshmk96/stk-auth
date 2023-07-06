package services_test

import (
	"testing"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCheckUserInGroup(t *testing.T) {
	t.Run("CheckUserInGroup returns true when user is in group", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("CheckUserGroupAssociation", userId.String(), groupId).Return(true, nil).Once()

		groupService := services.NewUserManagementService(storage)

		isUserInGroup, err := groupService.CheckUserInGroup(userId, groupId)
		assert.NoError(t, err)
		assert.True(t, isUserInGroup)

	})

	t.Run("CheckUserInGroup returns false when user is not in group", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("CheckUserGroupAssociation", userId.String(), groupId).Return(false, nil).Once()

		groupService := services.NewUserManagementService(storage)

		isUserInGroup, err := groupService.CheckUserInGroup(userId, groupId)
		assert.NoError(t, err)
		assert.False(t, isUserInGroup)

	})
}
func TestGetUserGroups(t *testing.T) {

	t.Run("GetUserGroups returns user groups without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())

		groups := []*entities.UserGroup{
			{
				ID:          "testGroupId1",
				Name:        "testGroup1",
				Description: "testDescription1",
			},
			{
				ID:          "testGroupId2",
				Name:        "testGroup2",
				Description: "testDescription2",
			},
		}

		storage.On("GetGroupsByUserID", userId.String()).Return(groups, nil).Once()

		groupService := services.NewUserManagementService(storage)

		userGroups, err := groupService.GetGroupsByUserID(userId)
		assert.NoError(t, err)
		assert.Equal(t, groups, userGroups)

		storage.AssertExpectations(t)
	})

	t.Run("GetUserGroups returns error when user groups are not retrieved", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())

		storage.On("GetGroupsByUserID", userId.String()).Return(nil, svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		userGroups, err := groupService.GetGroupsByUserID(userId)
		assert.Error(t, err)
		assert.Nil(t, userGroups)

		storage.AssertExpectations(t)
	})

	t.Run("GetUserGroups returns empty user groups when user has no groups", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())

		storage.On("GetGroupsByUserID", userId.String()).Return([]*entities.UserGroup{}, nil).Once()

		groupService := services.NewUserManagementService(storage)

		userGroups, err := groupService.GetGroupsByUserID(userId)
		assert.NoError(t, err)
		assert.Empty(t, userGroups)

		storage.AssertExpectations(t)
	})
}

func TestRemoveUserFromGrou(t *testing.T) {

	t.Run("RemoveUserFromGroup removes user from group without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("DeleteUserGroupAssociation", userId.String(), groupId).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.RemoveUserFromGroup(userId, groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("RemoveUserFromGroup returns error when user is not removed from group", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("DeleteUserGroupAssociation", userId.String(), groupId).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.RemoveUserFromGroup(userId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}
