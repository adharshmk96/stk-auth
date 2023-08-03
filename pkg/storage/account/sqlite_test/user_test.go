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

func TestAccountStorage_EmptyDatabase(t *testing.T) {

	conn := setupDatabase()

	conn.Exec(
		sqlite.Q_InsertAccountQuery,
		"invalid",
		"invalid",
		"invalid",
		"invalid",
		"invalid",
		time.Now(),
		time.Now(),
	)

	defer tearDownDatabase()

	accountId := ds.AccountID(uuid.New())
	time_now := time.Now()

	account := &ds.Account{
		ID:        accountId,
		Username:  "test",
		Password:  "test",
		Salt:      "salt",
		Email:     "account@test.com",
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetAccountByEmail returns error when email is not found in empty db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByEmail(account.Email)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByUsername returns error when username is not found in empty db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByUsername(account.Username)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByAccountID returns error when username is not found in empty db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByAccountID(account.Username)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByEmail get account by email returns error when parsing invalid id", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByEmail("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByUsername get account by username returns error when parsing invalid id", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByUsername("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByAccountID get account by username returns error when parsing invalid id", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByAccountID("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveAccount)
	})

	t.Run("SaveAccount saves account to database without error", func(t *testing.T) {
		err := accountStorage.SaveAccount(account)
		assert.NoError(t, err)
	})

	t.Run("SaveAccount returns error when same account is saved again", func(t *testing.T) {
		account := &ds.Account{
			ID:        ds.AccountID(uuid.New()),
			Username:  "test2",
			Password:  "test",
			Salt:      "salt",
			Email:     "account2@test.com",
			CreatedAt: time_now,
			UpdatedAt: time_now,
		}
		err := accountStorage.SaveAccount(account)
		assert.NoError(t, err)
		err = accountStorage.SaveAccount(account)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})

}

func TestAccountStorage_GetAccountByX(t *testing.T) {

	conn := setupDatabase()
	defer tearDownDatabase()

	accountId := ds.AccountID(uuid.New())
	time_now := time.Now()

	account := &ds.Account{
		ID:        accountId,
		Username:  "test",
		Password:  "test",
		Salt:      "salt",
		Email:     "account@test.com",
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	_, err := conn.Exec(
		sqlite.Q_InsertAccountQuery,
		account.ID.String(),
		account.Username,
		account.Password,
		account.Salt,
		account.Email,
		account.CreatedAt,
		account.UpdatedAt,
	)

	assert.NoError(t, err)
	t.Log("Account inserted successfully")

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetAccountByEmail retrieves account by email", func(t *testing.T) {
		retrievedAccount, err := accountStorage.GetAccountByEmail(account.Email)
		assert.NoError(t, err)
		assert.Equal(t, accountId, retrievedAccount.ID)
		assert.Equal(t, account.Username, retrievedAccount.Username)
		assert.Equal(t, account.Password, retrievedAccount.Password)
		assert.Equal(t, account.Salt, retrievedAccount.Salt)
		assert.Equal(t, account.Email, retrievedAccount.Email)
		assert.Equal(t, account.CreatedAt.Unix(), retrievedAccount.CreatedAt.Unix())
		assert.Equal(t, account.UpdatedAt.Unix(), retrievedAccount.UpdatedAt.Unix())
	})

	t.Run("GetAccountByUsername retrieves account by username", func(t *testing.T) {
		retrievedAccount, err := accountStorage.GetAccountByUsername(account.Username)
		assert.NoError(t, err)
		assert.Equal(t, accountId, retrievedAccount.ID)
		assert.Equal(t, account.Username, retrievedAccount.Username)
		assert.Equal(t, account.Password, retrievedAccount.Password)
		assert.Equal(t, account.Salt, retrievedAccount.Salt)
		assert.Equal(t, account.Email, retrievedAccount.Email)
		assert.Equal(t, account.CreatedAt.Unix(), retrievedAccount.CreatedAt.Unix())
		assert.Equal(t, account.UpdatedAt.Unix(), retrievedAccount.UpdatedAt.Unix())
	})

	t.Run("GetAccountByAccountID retrieves account by id", func(t *testing.T) {
		retrievedAccount, err := accountStorage.GetAccountByAccountID(accountId.String())
		assert.NoError(t, err)
		assert.Equal(t, accountId, retrievedAccount.ID)
		assert.Equal(t, account.Username, retrievedAccount.Username)
		assert.Equal(t, account.Password, retrievedAccount.Password)
		assert.Equal(t, account.Salt, retrievedAccount.Salt)
		assert.Equal(t, account.Email, retrievedAccount.Email)
		assert.Equal(t, account.CreatedAt.Unix(), retrievedAccount.CreatedAt.Unix())
		assert.Equal(t, account.UpdatedAt.Unix(), retrievedAccount.UpdatedAt.Unix())
	})

	t.Run("GetAccountByEmail returns error when id is not found in populated db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByEmail(account.Email + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByUsername returns error when id is not found in populated db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByUsername(account.Username + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})

	t.Run("GetAccountByAccountID returns error when id is not found in populated db", func(t *testing.T) {
		presaveAccount, err := accountStorage.GetAccountByAccountID(uuid.New().String())
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveAccount)
	})
}

func TestAccountStorage_UpdateAccountByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountId := ds.AccountID(uuid.New())
	username := "test"
	email := "test@account.com"
	password := "test"
	salt := "test"
	time_now := time.Now()

	account := &ds.Account{
		ID:        accountId,
		Username:  username,
		Password:  password,
		Salt:      salt,
		Email:     email,
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}
	conn.Exec(
		sqlite.Q_InsertAccountQuery,
		account.ID.String(),
		account.Username,
		account.Password,
		account.Salt,
		account.Email,
		account.CreatedAt,
		account.UpdatedAt,
	)

	t.Run("UpdateAccountByID updates account succesfully", func(t *testing.T) {
		accountStorage := sqlite.NewAccountStorage(conn)

		newUsername := "newUsername"
		newEmail := "account@email.com"
		newPassword := "newPassword"
		newSalt := "newSalt"
		newUpdatedAt := time.Now()

		newAccount := &ds.Account{
			ID:        accountId,
			Username:  newUsername,
			Email:     newEmail,
			Password:  newPassword,
			Salt:      newSalt,
			UpdatedAt: newUpdatedAt,
		}

		err := accountStorage.UpdateAccountByID(newAccount)

		assert.NoError(t, err)

		retrievedAccount, err := accountStorage.GetAccountByAccountID(accountId.String())

		assert.NoError(t, err)
		assert.Equal(t, newAccount.ID.String(), retrievedAccount.ID.String())
		assert.Equal(t, newAccount.Username, retrievedAccount.Username)
		assert.Equal(t, newAccount.Email, retrievedAccount.Email)
		assert.Equal(t, newAccount.Password, retrievedAccount.Password)
		assert.Equal(t, newAccount.Salt, retrievedAccount.Salt)
		assert.Equal(t, newAccount.UpdatedAt.Unix(), retrievedAccount.UpdatedAt.Unix())
		assert.Equal(t, time_now.Unix(), retrievedAccount.CreatedAt.Unix())
	})

	t.Run("UpdateAccountByID returns error when account is not found in populated db", func(t *testing.T) {
		accountStorage := sqlite.NewAccountStorage(conn)

		newUsername := "newUsername"
		newEmail := "newEmail"
		newPassword := "newPassword"
		newSalt := "newSalt"
		newUpdatedAt := time.Now()

		newAccount := &ds.Account{
			ID:        ds.AccountID(uuid.New()),
			Username:  newUsername,
			Email:     newEmail,
			Password:  newPassword,
			Salt:      newSalt,
			UpdatedAt: newUpdatedAt,
		}

		err := accountStorage.UpdateAccountByID(newAccount)

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

	t.Run("error when same email is found in for different account in db", func(t *testing.T) {
		newAccount := generateRandomAccount()

		accountStorage := sqlite.NewAccountStorage(conn)
		accountStorage.SaveAccount(newAccount)

		collissionAccount := generateRandomAccount()
		accountStorage.SaveAccount(collissionAccount)

		retrievedAccount, err := accountStorage.GetAccountByAccountID(collissionAccount.ID.String())
		assert.NoError(t, err)
		assert.Equal(t, collissionAccount.ID.String(), retrievedAccount.ID.String())

		collissionAccount.Email = newAccount.Email
		err = accountStorage.UpdateAccountByID(collissionAccount)

		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})
}

func generateRandomAccounts(n int) []*ds.Account {
	accounts := make([]*ds.Account, n)
	for i := 0; i < n; i++ {
		accounts[i] = generateRandomAccount()
	}
	return accounts
}

func TestAccountStorage_GetAccountList(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetAccountList returns empty list when db is empty", func(t *testing.T) {
		accounts, err := accountStorage.GetAccountList(0, 0)
		assert.NoError(t, err)
		assert.Empty(t, accounts)
	})

	accounts := generateRandomAccounts(30)
	for _, account := range accounts {
		accountStorage.SaveAccount(account)
	}

	t.Run("GetAccountList returns list of 10 accounts when limit requested is 0", func(t *testing.T) {

		retrievedAccounts, err := accountStorage.GetAccountList(20, 0)
		assert.NoError(t, err)
		assert.Equal(t, 20, len(retrievedAccounts))
		for i := 0; i < 20; i++ {
			assert.Equal(t, accounts[i].ID.String(), retrievedAccounts[i].ID.String())
			assert.Equal(t, accounts[i].Username, retrievedAccounts[i].Username)
			assert.Equal(t, accounts[i].Email, retrievedAccounts[i].Email)
			assert.Equal(t, accounts[i].UpdatedAt.Unix(), retrievedAccounts[i].UpdatedAt.Unix())
			assert.Equal(t, accounts[i].CreatedAt.Unix(), retrievedAccounts[i].CreatedAt.Unix())
		}
	})

	t.Run("GetAccountList returns list of accounts with offset", func(t *testing.T) {
		retrievedAccounts, err := accountStorage.GetAccountList(20, 10)
		assert.NoError(t, err)
		assert.Equal(t, 20, len(retrievedAccounts))
		for i := 0; i < 20; i++ {
			assert.Equal(t, accounts[i+10].ID.String(), retrievedAccounts[i].ID.String())
			assert.Equal(t, accounts[i+10].Username, retrievedAccounts[i].Username)
			assert.Equal(t, accounts[i+10].Email, retrievedAccounts[i].Email)
			assert.Equal(t, accounts[i+10].UpdatedAt.Unix(), retrievedAccounts[i].UpdatedAt.Unix())
			assert.Equal(t, accounts[i+10].CreatedAt.Unix(), retrievedAccounts[i].CreatedAt.Unix())
		}
	})
}

func TestAccountStorage_DeleteAccountByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("DeleteAccountByID returns error when account is not found in populated db", func(t *testing.T) {
		err := accountStorage.DeleteAccountByID(uuid.New().String())
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

	t.Run("DeleteAccountByID deletes account succesfully", func(t *testing.T) {
		account := generateRandomAccount()
		accountStorage.SaveAccount(account)

		retrievedAccount, err := accountStorage.GetAccountByAccountID(account.ID.String())
		assert.NoError(t, err)
		assert.Equal(t, account.ID.String(), retrievedAccount.ID.String())

		err = accountStorage.DeleteAccountByID(account.ID.String())
		assert.NoError(t, err)

		retrievedAccount, err = accountStorage.GetAccountByAccountID(account.ID.String())
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})
}

func TestAccountStore_GetTotalAccountCount(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	accountStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetTotalAccountCount returns 0 when db is empty", func(t *testing.T) {
		count, err := accountStorage.GetTotalAccountsCount()
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	accounts := generateRandomAccounts(30)
	for _, account := range accounts {
		accountStorage.SaveAccount(account)
	}

	t.Run("GetTotalAccountCount returns total account count", func(t *testing.T) {
		count, err := accountStorage.GetTotalAccountsCount()
		assert.NoError(t, err)
		assert.Equal(t, int64(30), count)
	})
}
