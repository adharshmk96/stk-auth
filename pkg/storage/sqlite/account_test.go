package sqlite_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/storage/sqlite"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func setupDatabase() *sql.DB {
	// this singleton pattern has a global effect. So it will make sure storage uses this instance.
	conn := db.GetSqliteConnection(":memory:")

	_, err := conn.Exec(`CREATE TABLE auth_user_accounts (
		id TEXT PRIMARY KEY UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		salt TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		panic(err)
	}

	return conn
}

func tearDownDatabase() {
	conn := db.GetSqliteConnection(":memory:")
	conn.Close()
}

func TestSaveAndRetrieveUser(t *testing.T) {

	setupDatabase()
	defer tearDownDatabase()

	userId := uuid.New()

	user := &entities.Account{
		ID:        entities.UserID(userId),
		Username:  "test",
		Password:  "test",
		Salt:      "salt",
		Email:     "user@test.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	userStorage := sqlite.NewAccountStorage()

	t.Run("returns error when account is not found", func(t *testing.T) {
		presaveUser, err := userStorage.GetUserByID(entities.UserID(userId))
		assert.EqualError(t, err, svrerr.ErrAccountNotFound.Error())
		assert.Nil(t, presaveUser)
	})

	t.Run("saves user to database", func(t *testing.T) {
		err := userStorage.SaveUser(user)
		assert.NoError(t, err)

	})

	t.Run("retrieves user by id", func(t *testing.T) {
		userStorage := sqlite.NewAccountStorage()
		retrievedUser, err := userStorage.GetUserByID(entities.UserID(userId))
		assert.NoError(t, err)
		assert.Equal(t, userId, userId)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Password, retrievedUser.Password)
		assert.Equal(t, user.Salt, retrievedUser.Salt)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.CreatedAt.Unix(), retrievedUser.CreatedAt.Unix())
		assert.Equal(t, user.UpdatedAt.Unix(), retrievedUser.UpdatedAt.Unix())
	})

	t.Run("returns error if user is not found", func(t *testing.T) {
		userStorage := sqlite.NewAccountStorage()
		user, err := userStorage.GetUserByID(entities.UserID(uuid.New()))
		assert.Nil(t, user)
		assert.Error(t, err)
		assert.EqualError(t, err, svrerr.ErrAccountNotFound.Error())
	})
}
