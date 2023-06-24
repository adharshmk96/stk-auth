package sqlite

import (
	"database/sql"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/infra"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/db"
)

var logger = infra.GetLogger()

type sqliteStorage struct {
	conn *sql.DB
}

func NewAccountStorage() entities.AccountStore {
	connection := db.GetSqliteConnection(sqlitePath)
	return &sqliteStorage{
		conn: connection,
	}
}

// TODO: Implement this
func (s *sqliteStorage) SaveUser(user *entities.Account) error {

	result, err := s.conn.Exec(
		INSERT_USER_QUERY,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		logger.Error("error inserting user into database: ", err)
		return svrerr.ErrStoringAccount
	}

	rows, err := result.RowsAffected()
	if rows == 0 || err != nil {
		logger.Error("error inserting user into database: ", err)
		return svrerr.ErrStoringAccount
	}

	return nil
}

// TODO: Implement this
func (s *sqliteStorage) GetUserByID(id entities.UserID) (*entities.Account, error) {

	row := s.conn.QueryRow(GET_USER_BY_ID, id.String())

	var userId string
	var user entities.Account
	err := row.Scan(
		&userId,
		&user.Username,
		&user.Password,
		&user.Salt,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrNoAccountFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, err
	}

	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}
