package sqlite

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveSession Stores Session in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
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
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// GetSessionByID Retrieves Valid Sessions from the db by session id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingUserID
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
		if errors.Is(err, sql.ErrNoRows) {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBStorageFailed
	}

	session.UserID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, svrerr.ErrParsingUserID
	}

	return &session, nil
}

// GetUserBySessionID Retrieves Session from the db by user id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingUserID
func (s *sqliteStorage) GetUserBySessionID(sessionId string) (*entities.Account, error) {
	row := s.conn.QueryRow(ACCOUNT_RETRIEVE_USER_BY_SESSION_ID, sessionId)

	var userId string
	var user entities.Account
	var username sql.NullString
	err := row.Scan(
		&userId,
		&username,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving user from database: ", err)
		return nil, svrerr.ErrDBStorageFailed
	}

	user.Username = username.String
	user.ID, err = entities.ParseUserId(userId)
	if err != nil {
		logger.Error("error parsing user id: ", err)
		return nil, err
	}

	return &user, nil
}

// InvalidateSessionByID Invalidates Session in the db by session id
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) InvalidateSessionByID(sessionId string) error {
	result, err := s.conn.Exec(
		ACCOUNT_INVALIDATE_SESSION_ID,
		sessionId,
	)
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("session not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}
