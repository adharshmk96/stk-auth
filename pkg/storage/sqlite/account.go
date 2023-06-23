package sqlite

import (
	"database/sql"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/stk/db"
)

type sqliteStorage struct {
	conn *sql.DB
}

const (
	sqlitePath = "sqlite.db"
)

func NewAccountStorage() entities.AccountStore {
	connection := db.GetSqliteConnection(sqlitePath)
	return &sqliteStorage{
		conn: connection,
	}
}

// TODO: Implement this
func (s *sqliteStorage) SaveUser(user *entities.Account) error {
	// query := "INSERT INTO users (username, password, email) VALUES (?, ?, ?)"
	// result, err := s.conn.Exec(query, user.Username, user.Password, user.Email)
	// if err != nil {
	// 	return &entities.Account{}, err
	// }
	// _, err = result.LastInsertId()
	// if err != nil {
	// 	return &entities.Account{}, err
	// }
	return nil
}

// TODO: Implement this
func (s *sqliteStorage) GetUserByID(id entities.UserID) (*entities.Account, error) {
	query := "SELECT id, username, password, email FROM users WHERE id = ?"
	row := s.conn.QueryRow(query, id)
	var user entities.Account
	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.Email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
