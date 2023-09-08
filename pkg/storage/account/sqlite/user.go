package sqlite

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveAccount Stores Account in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveAccount(account *ds.Account) error {

	result, err := s.conn.Exec(
		Q_InsertAccountQuery,
		account.ID.String(),
		NewNullString(account.Username),
		account.Password,
		account.Salt,
		account.Email,
		account.CreatedAt,
		account.UpdatedAt,
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

// GetAccountByEmail Retrieves Account from the db by email
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingAccountID
func (s *sqliteStorage) GetAccountByEmail(email string) (*ds.Account, error) {

	row := s.conn.QueryRow(Q_GetAccountByEmail, email)

	var accountId string
	var account ds.Account
	var username sql.NullString
	err := row.Scan(
		&accountId,
		&username,
		&account.Password,
		&account.Salt,
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
		return nil, svrerr.ErrParsingAccountID
	}

	return &account, nil
}

// GetAccountByUsername Retrieves Account from the db by username
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingAccountID
func (s *sqliteStorage) GetAccountByUsername(uname string) (*ds.Account, error) {

	row := s.conn.QueryRow(Q_GetAccountByUsername, uname)

	var accountId string
	var account ds.Account
	var username sql.NullString
	err := row.Scan(
		&accountId,
		&username,
		&account.Password,
		&account.Salt,
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
		return nil, svrerr.ErrDBStorageFailed
	}

	return &account, nil
}

// GetAccountByAccountID Retrieves Account from the db by account id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingAccountID
func (s *sqliteStorage) GetAccountByAccountID(uid string) (*ds.Account, error) {

	row := s.conn.QueryRow(Q_GetAccountByID, uid)

	var accountId string
	var account ds.Account
	var username sql.NullString
	err := row.Scan(
		&accountId,
		&username,
		&account.Password,
		&account.Salt,
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

// UpdateAccountByID Updates Account in the db by account id
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) UpdateAccountByID(account *ds.Account) error {
	userName := NewNullString(account.Username)
	result, err := s.conn.Exec(
		Q_UpdateAccountByID,
		userName,
		account.Email,
		account.Password,
		account.Salt,
		account.UpdatedAt,
		account.ID.String(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return svrerr.ErrDBDuplicateEntry
		}
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("account not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// GetAccountList Retrieves Account list from the db
// ERRORS: ErrDBRetrievingData
func (s *sqliteStorage) GetAccountList(limit int, offset int) ([]*ds.Account, error) {

	rows, err := s.conn.Query(Q_GetAccountList, limit, offset)
	if err != nil {
		logger.Error("storage_error:", err)
		return nil, svrerr.ErrDBStorageFailed
	}
	defer rows.Close()

	var accounts []*ds.Account
	for rows.Next() {
		var accountId string
		var account ds.Account
		var username sql.NullString
		err := rows.Scan(
			&accountId,
			&username,
			&account.Email,
			&account.CreatedAt,
			&account.UpdatedAt,
		)
		if err != nil {
			logger.Error("storage_error:", err)
			return nil, svrerr.ErrDBStorageFailed
		}

		account.Username = username.String
		account.ID, err = ds.ParseAccountId(accountId)
		if err != nil {
			logger.Error("error parsing account id: ", err)
			return nil, svrerr.ErrDBStorageFailed
		}

		accounts = append(accounts, &account)
	}

	return accounts, nil
}

// GetTotalAccountsCount Retrieves total number of accounts from the db
// ERRORS: ErrDBRetrievingData
func (s *sqliteStorage) GetTotalAccountsCount() (int64, error) {

	row := s.conn.QueryRow(Q_GetTotalAccountCount)

	var count int64
	err := row.Scan(&count)
	if err != nil {
		logger.Error("storage_error:", err)
		return 0, svrerr.ErrDBStorageFailed
	}

	return count, nil
}

func (s *sqliteStorage) DeleteAccountByID(uid string) error {
	result, err := s.conn.Exec(Q_DeleteAccountByID, uid)
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("account not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// SavePasswordResetToken Stores PasswordResetToken in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SavePasswordResetToken(id string, token string, expiry time.Time) error {

	result, err := s.conn.Exec(
		Q_InsertPasswordResetToken,
		id,
		token,
		expiry,
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

// GetPasswordResetToken Retrieves PasswordResetToken from the db
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound
func (s *sqliteStorage) GetPasswordResetToken(token string) (*ds.PasswordResetToken, error) {

	row := s.conn.QueryRow(Q_GetPasswordResetToken, token)

	var passwordResetToken ds.PasswordResetToken
	err := row.Scan(
		&passwordResetToken.AccountID,
		&passwordResetToken.Token,
		&passwordResetToken.Expiry,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving account from database: ", err)
		return nil, svrerr.ErrDBStorageFailed
	}

	return &passwordResetToken, nil
}

// GetAccountByPasswordResetToken Retrieves Account from the db by password reset token
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingAccountID
func (s *sqliteStorage) GetAccountByPasswordResetToken(token string) (*ds.Account, error) {

	row := s.conn.QueryRow(Q_GetAccountByPasswordResetToken, token)

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
		return nil, svrerr.ErrDBStorageFailed
	}

	return &account, nil
}

// InvalidateResetToken Invalidates PasswordResetToken in the db
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) InvalidateResetToken(token string) error {
	result, err := s.conn.Exec(Q_InvalidateResetToken, token)
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("token not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}
