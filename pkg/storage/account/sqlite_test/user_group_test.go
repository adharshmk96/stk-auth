package sqlite_test

import (
	"testing"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/storage/account/sqlite"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSaveGroupAssociation(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	conn.Exec("select * from auth_account_group_associations")

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

	t.Run("SaveGroupAssociation saves group association to database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		accountId := uuid.New()

		groupAssociation := &ds.AccountGroupAssociation{
			AccountID: ds.AccountID(accountId),
			GroupID:   groupId,
		}

		err := groupStorage.SaveGroupAssociation(groupAssociation)

		assert.NoError(t, err)
	})

	t.Run("SaveGroupAssociation returns error when same group association is saved again", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		accountId := uuid.New()

		groupAssociation := &ds.AccountGroupAssociation{
			AccountID: ds.AccountID(accountId),
			GroupID:   groupId,
		}

		err := groupStorage.SaveGroupAssociation(groupAssociation)

		assert.NoError(t, err)

		err = groupStorage.SaveGroupAssociation(groupAssociation)

		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})
}

func TestGetGroupsByAccountId(t *testing.T) {
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

	t.Run("GetGroupsByAccountId returns groups from database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		accountId := uuid.New()

		groupAssociation := &ds.AccountGroupAssociation{
			AccountID: ds.AccountID(accountId),
			GroupID:   groupId,
		}

		groupStorage.SaveGroupAssociation(groupAssociation)

		groups, err := groupStorage.GetGroupsByAccountID(accountId.String())

		assert.NoError(t, err)
		assert.Equal(t, 1, len(groups))
		assert.Equal(t, groupId, groups[0].ID)
		assert.Equal(t, groupName, groups[0].Name)
		assert.Equal(t, time_now.Unix(), groups[0].CreatedAt.Unix())
		assert.Equal(t, time_now.Unix(), groups[0].UpdatedAt.Unix())
	})

	t.Run("GetGroupsByAccountId returns error when account is not found in populated db", func(t *testing.T) {
		_, err := groupStorage.GetGroupsByAccountID(uuid.NewString())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}

func TestDeleteAccountGroupAssociation(t *testing.T) {
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

	t.Run("DeleteAccountGroupAssociation deletes group association from database without error", func(t *testing.T) {
		groupStorage.SaveGroup(group)

		accountId := uuid.New()

		groupAssociation := &ds.AccountGroupAssociation{
			AccountID: ds.AccountID(accountId),
			GroupID:   groupId,
		}

		groupStorage.SaveGroupAssociation(groupAssociation)

		err := groupStorage.DeleteAccountGroupAssociation(accountId.String(), groupId)

		assert.NoError(t, err)

		_, err = groupStorage.GetGroupsByAccountID(accountId.String())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

	t.Run("DeleteAccountGroupAssociation returns error when group association is not found in populated db", func(t *testing.T) {
		err := groupStorage.DeleteAccountGroupAssociation(uuid.NewString(), uuid.NewString())

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}
