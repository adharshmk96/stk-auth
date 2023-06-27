package sqlite

import (
	"database/sql"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/storage"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
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
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return svrerr.ErrDBDuplicateEntry
		}
		logger.Error("error inserting user into database: ", err)
		return svrerr.ErrDBStoringData
	}

	_, err = result.RowsAffected()
	if err != nil {
		logger.Error(err)
		return svrerr.ErrDBStoringData
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
		if err == sql.ErrNoRows {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBRetrievingData
	}

	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}

func (s *sqliteStorage) GetUserByUsername(username string) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_USERNAME, username)

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
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBRetrievingData
	}

	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}

func (s *sqliteStorage) GetUserByUserID(uid string) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_ID, uid)

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
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBRetrievingData
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
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return svrerr.ErrDBDuplicateEntry
		}
		logger.Error("error inserting user into database: ", err)
		return svrerr.ErrDBStoringData
	}

	_, err = result.RowsAffected()
	if err != nil {
		logger.Error(err)
		return svrerr.ErrDBStoringData
	}

	return nil
}

func (s *sqliteStorage) GetSessionByID(sessionID string) (*entities.Session, error) {
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
		if err == sql.ErrNoRows {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBRetrievingData
	}

	session.UserID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &session, nil
}

func (s *sqliteStorage) GetUserBySessionID(sessionId string) (*entities.Account, error) {
	row := s.conn.QueryRow(ACCOUNT_RETRIEVE_USER_BY_SESSION_ID, sessionId)

	var userId string
	var user entities.Account
	err := row.Scan(
		&userId,
		&user.Username,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBRetrievingData
	}

	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}

func (s *sqliteStorage) InvalidateSessionByID(sessionId string) error {
	result, err := s.conn.Exec(
		ACCOUNT_INVALIDATE_SESSION_ID,
		sessionId,
	)
	if err != nil {
		logger.Error("error invalidating session: ", err)
		return svrerr.ErrDBUpdatingData
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("session not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error(err)
		return svrerr.ErrDBStoringData
	}

	return nil
}
