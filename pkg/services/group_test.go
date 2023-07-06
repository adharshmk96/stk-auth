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

func TestCreateGroup(t *testing.T) {

	t.Run("CreateGroup creates group without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		group := &entities.UserGroup{
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
		storage := mocks.NewUserManagementStore(t)

		group := &entities.UserGroup{
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

func TestAddUserToGroup(t *testing.T) {

	t.Run("AddUserToGroup adds user to group without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*entities.UserGroupAssociation")).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.AddUserToGroup(userId, groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("AddUserToGroup returns error when user is not added to group", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*entities.UserGroupAssociation")).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.AddUserToGroup(userId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("returns error when same user is added to group again", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		userId := entities.UserID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*entities.UserGroupAssociation")).Return(svrerr.ErrDBDuplicateEntry).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.AddUserToGroup(userId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}

func TestUpdateGroupByID(t *testing.T) {

	t.Run("UpdateGroupByID updates group without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		group := &entities.UserGroup{
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
		storage := mocks.NewUserManagementStore(t)

		group := &entities.UserGroup{
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

func TestDeleteGroupByID(t *testing.T) {

	t.Run("DeleteGroupByID deletes group without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		groupId := "testGroupId"

		storage.On("DeleteGroupByID", groupId).Return(nil).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.DeleteGroupByID(groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("DeleteGroupByID returns error when group is not deleted", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		groupId := "testGroupId"

		storage.On("DeleteGroupByID", groupId).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewUserManagementService(storage)

		err := groupService.DeleteGroupByID(groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}
