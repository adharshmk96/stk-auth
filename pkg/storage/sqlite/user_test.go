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

func TestUserStorage_EmptyDatabase(t *testing.T) {

	conn := setupDatabase()
	defer tearDownDatabase()

	userId := entities.UserID(uuid.New())
	time_now := time.Now()

	user := &entities.Account{
		ID:        userId,
		Username:  "test",
		Password:  "test",
		Salt:      "salt",
		Email:     "user@test.com",
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetUserByEmail returns error when email is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail(user.Email)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUsername returns error when username is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername(user.Username)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUserID returns error when username is not found in empty db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUserID(user.Username)
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByEmail get user by email returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUsername get user by username returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUserID get user by username returns error when parsing invalid id", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUserID("invalid")
		assert.Error(t, err)
		assert.Nil(t, presaveUser)
	})

	t.Run("SaveUser saves user to database without error", func(t *testing.T) {
		err := userStorage.SaveUser(user)
		assert.NoError(t, err)
	})

	t.Run("SaveUser returns error when same user is saved again", func(t *testing.T) {
		user := &entities.Account{
			ID:        entities.UserID(uuid.New()),
			Username:  "test2",
			Password:  "test",
			Salt:      "salt",
			Email:     "user2@test.com",
			CreatedAt: time_now,
			UpdatedAt: time_now,
		}
		err := userStorage.SaveUser(user)
		assert.NoError(t, err)
		err = userStorage.SaveUser(user)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})

}

func TestUserStorage_GetUserByX(t *testing.T) {

	conn := setupDatabase()
	defer tearDownDatabase()

	userId := entities.UserID(uuid.New())
	time_now := time.Now()

	user := &entities.Account{
		ID:        userId,
		Username:  "test",
		Password:  "test",
		Salt:      "salt",
		Email:     "user@test.com",
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	_, err := conn.Exec(
		sqlite.ACCOUNT_INSERT_USER_QUERY,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)

	assert.NoError(t, err)
	t.Log("User inserted successfully")

	userStorage := sqlite.NewAccountStorage(conn)

	t.Run("GetUserByEmail retrieves user by email", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserByEmail(user.Email)
		assert.NoError(t, err)
		assert.Equal(t, userId, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("GetUserByUsername retrieves user by username", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserByUsername(user.Username)
		assert.NoError(t, err)
		assert.Equal(t, userId, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("GetUserByUserID retrieves user by id", func(t *testing.T) {
		retrievedUser, err := userStorage.GetUserByUserID(userId.String())
		assert.NoError(t, err)
		assert.Equal(t, userId, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("GetUserByEmail returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByEmail(user.Email + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUsername returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUsername(user.Username + "xd")
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("GetUserByUserID returns error when id is not found in populated db", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByUserID(uuid.New().String())
		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
		assert.Nil(t, presaveUser)
	})
}

func TestUserStorage_UpdateUserByID(t *testing.T) {
	conn := setupDatabase()
	defer tearDownDatabase()

	userId := entities.UserID(uuid.New())
	username := "test"
	email := "test@user.com"
	password := "test"
	salt := "test"
	time_now := time.Now()

	user := &entities.Account{
		ID:        userId,
		Username:  username,
		Password:  password,
		Salt:      salt,
		Email:     email,
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}
	conn.Exec(
		sqlite.ACCOUNT_INSERT_USER_QUERY,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)

	t.Run("UpdateUserByID updates user succesfully", func(t *testing.T) {
		userStorage := sqlite.NewAccountStorage(conn)

		newUsername := "newUsername"
		newEmail := "user@email.com"
		newPassword := "newPassword"
		newSalt := "newSalt"
		newUpdatedAt := time.Now()

		newUser := &entities.Account{
			ID:        userId,
			Username:  newUsername,
			Email:     newEmail,
			Password:  newPassword,
			Salt:      newSalt,
			UpdatedAt: newUpdatedAt,
		}

		err := userStorage.UpdateUserByID(newUser)

		assert.NoError(t, err)

		retrievedUser, err := userStorage.GetUserByUserID(userId.String())

		assert.NoError(t, err)
		assert.Equal(t, newUser.ID.String(), retrievedUser.ID.String())
		assert.Equal(t, newUser.Username, retrievedUser.Username)
		assert.Equal(t, newUser.Email, retrievedUser.Email)
		assert.Equal(t, newUser.Password, retrievedUser.Password)
		assert.Equal(t, newUser.Salt, retrievedUser.Salt)
		assert.Equal(t, newUser.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
		assert.Equal(t, time_now.Unix(), retrievedUser.CreatedAt.Unix())
	})

	t.Run("UpdateUserByID returns error when user is not found in populated db", func(t *testing.T) {
		userStorage := sqlite.NewAccountStorage(conn)

		newUsername := "newUsername"
		newEmail := "newEmail"
		newPassword := "newPassword"
		newSalt := "newSalt"
		newUpdatedAt := time.Now()

		newUser := &entities.Account{
			ID:        entities.UserID(uuid.New()),
			Username:  newUsername,
			Email:     newEmail,
			Password:  newPassword,
			Salt:      newSalt,
			UpdatedAt: newUpdatedAt,
		}

		err := userStorage.UpdateUserByID(newUser)

		assert.EqualError(t, err, svrerr.ErrDBEntryNotFound.Error())
	})

	t.Run("error when same email is found in for different user in db", func(t *testing.T) {
		newUser := generateRandomUser()

		userStorage := sqlite.NewAccountStorage(conn)
		userStorage.SaveUser(newUser)

		collissionUser := generateRandomUser()
		userStorage.SaveUser(collissionUser)

		retrievedUser, err := userStorage.GetUserByUserID(collissionUser.ID.String())
		assert.NoError(t, err)
		assert.Equal(t, collissionUser.ID.String(), retrievedUser.ID.String())

		collissionUser.Email = newUser.Email
		err = userStorage.UpdateUserByID(collissionUser)

		assert.EqualError(t, err, svrerr.ErrDBDuplicateEntry.Error())
	})
}