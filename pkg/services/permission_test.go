package services_test

import (
	"testing"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthenticationService_CreateGroup(t *testing.T) {

	t.Run("CreateGroup creates group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &entities.Group{
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("SaveGroup", group).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		createdGroup, err := groupService.CreateGroup(group)
		assert.NoError(t, err)
		assert.Equal(t, group.Name, createdGroup.Name)
		assert.Equal(t, group.Description, createdGroup.Description)
		assert.NotEmpty(t, createdGroup.ID)
		assert.NotEmpty(t, createdGroup.CreatedAt)
		assert.NotEmpty(t, createdGroup.UpdatedAt)

		storage.AssertExpectations(t)
	})

	t.Run("CreateGroup returns error when group is not saved", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &entities.Group{
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("SaveGroup", group).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		createdGroup, err := groupService.CreateGroup(group)
		assert.Error(t, err)
		assert.Nil(t, createdGroup)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_AddUserToGroup(t *testing.T) {

	t.Run("AddUserToGroup adds user to group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*entities.UserGroupAssociation")).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.AddUserToGroup(userId, groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("AddUserToGroup returns error when user is not added to group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*entities.UserGroupAssociation")).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.AddUserToGroup(userId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("returns error when same user is added to group again", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*entities.UserGroupAssociation")).Return(svrerr.ErrDBDuplicateEntry).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.AddUserToGroup(userId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_UpdateGroupByID(t *testing.T) {

	t.Run("UpdateGroupByID updates group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &entities.Group{
			ID:          "testGroupId",
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("UpdateGroup", group).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.UpdateGroupByID(group)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("UpdateGroupByID returns error when group is not updated", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &entities.Group{
			ID:          "testGroupId",
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("UpdateGroup", group).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.UpdateGroupByID(group)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_DeleteGroupByID(t *testing.T) {

	t.Run("DeleteGroupByID deletes group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		groupId := "testGroupId"

		storage.On("DeleteGroupByID", groupId).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.DeleteGroupByID(groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("DeleteGroupByID returns error when group is not deleted", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		groupId := "testGroupId"

		storage.On("DeleteGroupByID", groupId).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.DeleteGroupByID(groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_CheckUserInGroup(t *testing.T) {
	t.Run("CheckUserInGroup returns true when user is in group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("CheckUserGroupAssociation", userId.String(), groupId).Return(true, nil).Once()

		groupService := services.NewUserManagementService(storage)

		isUserInGroup, err := groupService.CheckUserInGroup(userId, groupId)
		assert.NoError(t, err)
		assert.True(t, isUserInGroup)

	})

	t.Run("CheckUserInGroup returns false when user is not in group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("CheckUserGroupAssociation", userId.String(), groupId).Return(false, nil).Once()

		groupService := services.NewUserManagementService(storage)

		isUserInGroup, err := groupService.CheckUserInGroup(userId, groupId)
		assert.NoError(t, err)
		assert.False(t, isUserInGroup)

	})
}
func TestAuthenticationService_GetUserGroups(t *testing.T) {

	t.Run("GetUserGroups returns user groups without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())

		groups := []*entities.Group{
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
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())

		storage.On("GetGroupsByUserID", userId.String()).Return(nil, svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		userGroups, err := groupService.GetGroupsByUserID(userId)
		assert.Error(t, err)
		assert.Nil(t, userGroups)

		storage.AssertExpectations(t)
	})

	t.Run("GetUserGroups returns empty user groups when user has no groups", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())

		storage.On("GetGroupsByUserID", userId.String()).Return([]*entities.Group{}, nil).Once()

		groupService := services.NewUserManagementService(storage)

		userGroups, err := groupService.GetGroupsByUserID(userId)
		assert.NoError(t, err)
		assert.Empty(t, userGroups)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_RemoveUserFromGrou(t *testing.T) {

	t.Run("RemoveUserFromGroup removes user from group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("DeleteUserGroupAssociation", userId.String(), groupId).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.RemoveUserFromGroup(userId, groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("RemoveUserFromGroup returns error when user is not removed from group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("DeleteUserGroupAssociation", userId.String(), groupId).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.RemoveUserFromGroup(userId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}
