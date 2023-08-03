package sqlite

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveSession Stores Session in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveSession(session *ds.Session) error {
	result, err := s.conn.Exec(
		Q_InsertSession,
		session.AccountID.String(),
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
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingAccountID
func (s *sqliteStorage) GetSessionByID(sessionID string) (*ds.Session, error) {
	row := s.conn.QueryRow(Q_GetSessionByID, sessionID)

	var accountId string
	var session ds.Session
	err := row.Scan(
		&accountId,
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

		logger.Error("error retrieving account from database: ", err)
		return nil, svrerr.ErrDBStorageFailed
	}

	session.AccountID, err = ds.ParseAccountId(accountId)
	if err != nil {
		logger.Error("error parsing account id: ", err)
		return nil, svrerr.ErrParsingAccountID
	}

	return &session, nil
}

// GetAccountBySessionID Retrieves Session from the db by account id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingAccountID
func (s *sqliteStorage) GetAccountBySessionID(sessionId string) (*ds.Account, error) {
	row := s.conn.QueryRow(Q_GetAccountBySessionID, sessionId)

	var accountId string
	var account ds.Account
	var username sql.NullString
	err := row.Scan(
		&accountId,
		&username,
		&account.Email,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving account from database: ", err)
		return nil, svrerr.ErrDBStorageFailed
	}

	account.Username = username.String
	account.ID, err = ds.ParseAccountId(accountId)
	if err != nil {
		logger.Error("error parsing account id: ", err)
		return nil, err
	}

	return &account, nil
}

// InvalidateSessionByID Invalidates Session in the db by session id
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) InvalidateSessionByID(sessionId string) error {
	result, err := s.conn.Exec(
		Q_InvalidateSession,
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
