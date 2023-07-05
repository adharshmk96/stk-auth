package services_test

import (
	"testing"

	"github.com/adharshmk96/stk-auth/mocks"
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/stretchr/testify/assert"
)

func TestCreateGroup(t *testing.T) {

	t.Run("CreateGroup creates group without error", func(t *testing.T) {
		storage := mocks.NewUserManagementStore(t)

		group := &entities.UserGroup{
			Name:        "testGroup",
			Description: "testDescription",
		}

		storage.On("SaveGroup", group).Return(nil).Once()

		groupService := services.NewAccountService(storage)

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

		groupService := services.NewAccountService(storage)

		createdGroup, err := groupService.CreateGroup(group)
		assert.Error(t, err)
		assert.Nil(t, createdGroup)

		storage.AssertExpectations(t)
	})
}
