package services_test

import (
	"testing"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthenticationService_CreateGroup(t *testing.T) {

	t.Run("CreateGroup creates group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &ds.Group{
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("SaveGroup", group).Return(nil).Once()

		groupService := services.NewAuthenticationService(storage)

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

		group := &ds.Group{
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("SaveGroup", group).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewAuthenticationService(storage)

		createdGroup, err := groupService.CreateGroup(group)
		assert.Error(t, err)
		assert.Nil(t, createdGroup)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_AddAccountToGroup(t *testing.T) {

	t.Run("AddAccountToGroup adds account to group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*ds.AccountGroupAssociation")).Return(nil).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.AddAccountToGroup(accountId, groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("AddAccountToGroup returns error when account is not added to group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*ds.AccountGroupAssociation")).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.AddAccountToGroup(accountId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("returns error when same account is added to group again", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("SaveGroupAssociation", mock.AnythingOfType("*ds.AccountGroupAssociation")).Return(svrerr.ErrDBDuplicateEntry).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.AddAccountToGroup(accountId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_UpdateGroupByID(t *testing.T) {

	t.Run("UpdateGroupByID updates group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &ds.Group{
			ID:          "testGroupId",
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("UpdateGroup", group).Return(nil).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.UpdateGroupByID(group)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("UpdateGroupByID returns error when group is not updated", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		group := &ds.Group{
			ID:          "testGroupId",
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("UpdateGroup", group).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewAuthenticationService(storage)

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

		groupService := services.NewAuthenticationService(storage)

		err := groupService.DeleteGroupByID(groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("DeleteGroupByID returns error when group is not deleted", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		groupId := "testGroupId"

		storage.On("DeleteGroupByID", groupId).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.DeleteGroupByID(groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_CheckAccountInGroup(t *testing.T) {
	t.Run("CheckAccountInGroup returns true when account is in group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("CheckAccountGroupAssociation", accountId.String(), groupId).Return(true, nil).Once()

		groupService := services.NewAuthenticationService(storage)

		isAccountInGroup, err := groupService.CheckAccountInGroup(accountId, groupId)
		assert.NoError(t, err)
		assert.True(t, isAccountInGroup)

	})

	t.Run("CheckAccountInGroup returns false when account is not in group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("CheckAccountGroupAssociation", accountId.String(), groupId).Return(false, nil).Once()

		groupService := services.NewAuthenticationService(storage)

		isAccountInGroup, err := groupService.CheckAccountInGroup(accountId, groupId)
		assert.NoError(t, err)
		assert.False(t, isAccountInGroup)

	})
}
func TestAuthenticationService_GetAccountGroups(t *testing.T) {

	t.Run("GetAccountGroups returns account groups without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())

		groups := []*ds.Group{
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

		storage.On("GetGroupsByAccountID", accountId.String()).Return(groups, nil).Once()

		groupService := services.NewAuthenticationService(storage)

		accountGroups, err := groupService.GetGroupsByAccountID(accountId)
		assert.NoError(t, err)
		assert.Equal(t, groups, accountGroups)

		storage.AssertExpectations(t)
	})

	t.Run("GetAccountGroups returns error when account groups are not retrieved", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())

		storage.On("GetGroupsByAccountID", accountId.String()).Return(nil, svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewAuthenticationService(storage)

		accountGroups, err := groupService.GetGroupsByAccountID(accountId)
		assert.Error(t, err)
		assert.Nil(t, accountGroups)

		storage.AssertExpectations(t)
	})

	t.Run("GetAccountGroups returns empty account groups when account has no groups", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())

		storage.On("GetGroupsByAccountID", accountId.String()).Return([]*ds.Group{}, nil).Once()

		groupService := services.NewAuthenticationService(storage)

		accountGroups, err := groupService.GetGroupsByAccountID(accountId)
		assert.NoError(t, err)
		assert.Empty(t, accountGroups)

		storage.AssertExpectations(t)
	})
}

func TestAuthenticationService_RemoveAccountFromGrou(t *testing.T) {

	t.Run("RemoveAccountFromGroup removes account from group without error", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("DeleteAccountGroupAssociation", accountId.String(), groupId).Return(nil).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.RemoveAccountFromGroup(accountId, groupId)
		assert.NoError(t, err)

		storage.AssertExpectations(t)
	})

	t.Run("RemoveAccountFromGroup returns error when account is not removed from group", func(t *testing.T) {
		storage := mocks.NewAuthenticationStore(t)

		accountId := ds.AccountID(uuid.New())
		groupId := "testGroupId"

		storage.On("DeleteAccountGroupAssociation", accountId.String(), groupId).Return(svrerr.ErrDBStorageFailed).Once()

		groupService := services.NewAuthenticationService(storage)

		err := groupService.RemoveAccountFromGroup(accountId, groupId)
		assert.Error(t, err)

		storage.AssertExpectations(t)
	})
}
