package sqlite_test

import (
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/storage/user/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSaveGroup(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &ds.Group{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	groupStorage := sqlite.NewAccountStorage(conn)

	t.Run("SaveGroup saves group to database without error", func(t *testing.T) {
		err := groupStorage.SaveGroup(group)
		assert.NoError(t, err)
	})

	t.Run("SaveGroup returns error when same group is saved again", func(t *testing.T) {
		group2 := &ds.Group{
			ID:          uuid.NewString(),
			Name:        groupName + "x",
			Description: "testDescription",
			CreatedAt:   time_now,
			UpdatedAt:   time_now,
		}

		err := groupStorage.SaveGroup(group2)
		assert.NoError(t, err)
		err = groupStorage.SaveGroup(group2)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})

}

func TestUpdateGroupById(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &ds.Group{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	t.Run("UpdateGroupByID updates group succesfully", func(t *testing.T) {
		groupStorage := sqlite.NewAccountStorage(conn)

		newGroupName := "newGroupName"
		newUpdatedAt := time.Now()

		newGroup := &ds.Group{
			ID:        groupId,
			Name:      newGroupName,
			UpdatedAt: newUpdatedAt,
		}

		groupStorage.SaveGroup(group)
		err := groupStorage.UpdateGroup(newGroup)

		assert.NoError(t, err)

		retrievedGroup, err := groupStorage.GetGroupByID(groupId)

		assert.NoError(t, err)
		assert.Equal(t, newGroup.ID, retrievedGroup.ID)
		assert.Equal(t, newGroup.Name, retrievedGroup.Name)
		assert.Equal(t, newGroup.UpdatedAt.Unix(), retrievedGroup.UpdatedAt.Unix())
		assert.Equal(t, time_now.Unix(), retrievedGroup.CreatedAt.Unix())
	})

	t.Run("UpdateGroupByID returns error when group is not found in populated db", func(t *testing.T) {
		groupStorage := sqlite.NewAccountStorage(conn)

		newGroupName := "newGroupName"
		newUpdatedAt := time.Now()

		newGroup := &ds.Group{
			ID:        uuid.NewString(),
			Name:      newGroupName,
			UpdatedAt: newUpdatedAt,
		}

		err := groupStorage.UpdateGroup(newGroup)

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

}

func TestGetGroupById(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &ds.Group{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	groupStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetGroupByID returns group from database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		retrievedGroup, err := groupStorage.GetGroupByID(groupId)

		assert.NoError(t, err)
		assert.Equal(t, group.ID, retrievedGroup.ID)
		assert.Equal(t, group.Name, retrievedGroup.Name)
		assert.Equal(t, group.UpdatedAt.Unix(), retrievedGroup.UpdatedAt.Unix())
		assert.Equal(t, time_now.Unix(), retrievedGroup.CreatedAt.Unix())
	})

	t.Run("GetGroupByID returns error when group is not found in populated db", func(t *testing.T) {
		_, err := groupStorage.GetGroupByID(uuid.NewString())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}

func TestDeleteGroupByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	groupId := uuid.NewString()
	groupName := "testGroup"
	time_now := time.Now()

	group := &ds.Group{
		ID:          groupId,
		Name:        groupName,
		Description: "testDescription",
		CreatedAt:   time_now,
		UpdatedAt:   time_now,
	}

	groupStorage := sqlite.NewAccountStorage(conn)

	t.Run("DeleteGroupByID deletes group from database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		err := groupStorage.DeleteGroupByID(groupId)

		assert.NoError(t, err)

		_, err = groupStorage.GetGroupByID(groupId)

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

	t.Run("DeleteGroupByID returns error when group is not found in populated db", func(t *testing.T) {
		err := groupStorage.DeleteGroupByID(uuid.NewString())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}
