package sqlite_test

import (
	"database/sql"
	"fmt"
	"os/exec"
	"testing"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/storage/sqlite"
	"github.com/adharshmk96/stk/db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func setupDatabase() *sql.DB {
	conn := db.GetSqliteConnection("sqlite.db")

	_, err := conn.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)")
	if err != nil {
		panic(err)
	}

	return conn

}

func tearDownDatabase() {
	fmt.Println("tearing down database")
	exec.Command("rm", "-f", "sqlite.db").Run()
}

func TestSaveAndRetrieveUser(t *testing.T) {

	conn := setupDatabase()
	defer tearDownDatabase()

	userId := uuid.New()

	user := &entities.User{
		ID:       entities.UserID(userId),
		Username: "test",
		Password: "test",
		Email:    "user@test.com",
	}

	t.Run("saves user in the database", func(t *testing.T) {
		userStorage := sqlite.NewUserStorage()

		id, err := userStorage.SaveUser(user)
		assert.NoError(t, err)
		assert.Equal(t, entities.UserID(userId), id)

		res, err := conn.Exec("select * from users")
		assert.NoError(t, err)

		rows, err := res.RowsAffected()
		t.Error(rows)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), rows)

	})

	t.Run("retrieves user by id", func(t *testing.T) {
		userStorage := sqlite.NewUserStorage()
		retrivedUser, err := userStorage.GetUserByID(entities.UserID(userId))
		assert.NoError(t, err)
		assert.Equal(t, user, retrivedUser)
	})
}
