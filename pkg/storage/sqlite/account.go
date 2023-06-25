package sqlite

import (
	"database/sql"
	"strings"

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

func (s *sqliteStorage) SaveUser(user *entities.Account) error {

	result, err := s.conn.Exec(
		ACCOUNT_INSERT_USER_QUERY,
		user.ID.String(),
		user.Username,
		user.Password,
		user.Salt,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return handleSaveError(err)
	}

	rows, err := result.RowsAffected()
	logger.Error("rows affected: " + string(rune(rows)))
	if err != nil {
		logger.Error("no rows affected: ", err)
		return svrerr.ErrStoringAccount
	}

	return nil
}

func handleSaveError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return svrerr.ErrAccountExists
	}
	logger.Error("error inserting user into database: ", err)
	return svrerr.ErrStoringAccount
}

func (s *sqliteStorage) GetUserByID(id entities.UserID) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_ID, id.String())

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
		return handleRetrieveErr(err)
	}

	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}

func handleRetrieveErr(err error) (*entities.Account, error) {
	if err == sql.ErrNoRows {
		logger.Error("record not found:", err)
		return nil, svrerr.ErrAccountNotFound
	}

	logger.Error("error retrieving user from database: ", err)
	return nil, svrerr.ErrRetrievingAccount
}
