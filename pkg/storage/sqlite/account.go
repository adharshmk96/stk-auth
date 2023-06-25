package sqlite

import (
	"database/sql"
	"strings"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/infra"
	"github.com/adharshmk96/auth-server/pkg/storage"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/db"
)

var logger = infra.GetLogger()

type sqliteStorage struct {
	conn *sql.DB
}

func NewAccountStorage() storage.AccountStore {
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
		return svrerr.ErrStoringData
	}

	return nil
}

func (s *sqliteStorage) GetUserByEmail(email string) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_EMAIL, email)

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
		return nil, handleRetrieveErr(err)
	}

	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}

func (s *sqliteStorage) SaveSession(session *entities.Session) error {
	result, err := s.conn.Exec(
		ACCOUNT_INSERT_SESSION_QUERY,
		session.UserID.String(),
		session.SessionID,
		session.CreatedAt,
		session.UpdatedAt,
		session.Valid,
	)
	if err != nil {
		return handleSaveError(err)
	}

	rows, err := result.RowsAffected()
	logger.Error("rows affected: " + string(rune(rows)))
	if err != nil {
		logger.Error("no rows affected: ", err)
		return svrerr.ErrStoringData
	}

	return nil
}

func (s *sqliteStorage) RetrieveSessionByID(sessionID string) (*entities.Session, error) {
	row := s.conn.QueryRow(ACCOUNT_RETRIEVE_SESSION_BY_ID, sessionID)

	var userId string
	var session entities.Session
	err := row.Scan(
		&userId,
		&session.SessionID,
		&session.CreatedAt,
		&session.UpdatedAt,
		&session.Valid,
	)

	if err != nil {
		return nil, handleRetrieveErr(err)
	}

	session.UserID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &session, nil

}

func handleSaveError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return svrerr.ErrDuplicateEntry
	}
	logger.Error("error inserting user into database: ", err)
	return svrerr.ErrStoringData
}

func handleRetrieveErr(err error) error {
	if err == sql.ErrNoRows {
		logger.Error("record not found:", err)
		return svrerr.ErrEntryNotFound
	}

	logger.Error("error retrieving user from database: ", err)
	return svrerr.ErrRetrievingData
}
