package sqlite_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/storage/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSaveGroupAssociation(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	conn.Exec("select * from auth_user_group_associations")

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &entities.UserGroup{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	groupStorage := sqlite.NewAccountStorage(conn)

	t.Run("SaveGroupAssociation saves group association to database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		userId := uuid.New()

		groupAssociation := &entities.UserGroupAssociation{
			UserID:  entities.UserID(userId),
			GroupID: groupId,
		}

		err := groupStorage.SaveGroupAssociation(groupAssociation)

		assert.NoError(t, err)
	})

	t.Run("SaveGroupAssociation returns error when same group association is saved again", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		userId := uuid.New()

		groupAssociation := &entities.UserGroupAssociation{
			UserID:  entities.UserID(userId),
			GroupID: groupId,
		}

		err := groupStorage.SaveGroupAssociation(groupAssociation)

		assert.NoError(t, err)

		err = groupStorage.SaveGroupAssociation(groupAssociation)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})
}

func TestGetGroupsByUserId(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &entities.UserGroup{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	groupStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetGroupsByUserId returns groups from database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		userId := uuid.New()

		groupAssociation := &entities.UserGroupAssociation{
			UserID:  entities.UserID(userId),
			GroupID: groupId,
		}

		groupStorage.SaveGroupAssociation(groupAssociation)

		groups, err := groupStorage.GetGroupsByUserID(userId.String())

		assert.NoError(t, err)
		assert.Equal(t, 1, len(groups))
		assert.Equal(t, groupId, groups[0].ID)
		assert.Equal(t, groupName, groups[0].Name)
		assert.Equal(t, time_now.Unix(), groups[0].CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), groups[0].UpdatedAt.Unix())
	})

	t.Run("GetGroupsByUserId returns error when user is not found in populated db", func(t *testing.T) {
		_, err := groupStorage.GetGroupsByUserID(uuid.NewString())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}

func TestDeleteUserGroupAssociation(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &entities.UserGroup{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	groupStorage := sqlite.NewAccountStorage(conn)

	t.Run("DeleteUserGroupAssociation deletes group association from database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		userId := uuid.New()

		groupAssociation := &entities.UserGroupAssociation{
			UserID:  entities.UserID(userId),
			GroupID: groupId,
		}

		groupStorage.SaveGroupAssociation(groupAssociation)

		err := groupStorage.DeleteUserGroupAssociation(userId.String(), groupId)

		assert.NoError(t, err)

		_, err = groupStorage.GetGroupsByUserID(userId.String())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

	t.Run("DeleteUserGroupAssociation returns error when group association is not found in populated db", func(t *testing.T) {
		err := groupStorage.DeleteUserGroupAssociation(uuid.NewString(), uuid.NewString())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}
