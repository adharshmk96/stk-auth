package sqlite

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveUser Stores User in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveUser(user *entities.Account) error {

	result, err := s.conn.Exec(
		ACCOUNT_INSERT_USER_QUERY,
		user.ID.String(),
		NewNullString(user.Username),
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

// GetUserByEmail Retrieves User from the db by email
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingUserID
func (s *sqliteStorage) GetUserByEmail(email string) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_EMAIL, email)

	var userId string
	var user entities.Account
	var username sql.NullString
	err := row.Scan(
		&userId,
		&username,
		&user.Password,
		&user.Salt,
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
		return nil, svrerr.ErrParsingUserID
	}

	return &user, nil
}

// GetUserByUsername Retrieves User from the db by username
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingUserID
func (s *sqliteStorage) GetUserByUsername(uname string) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_USERNAME, uname)

	var userId string
	var user entities.Account
	var username sql.NullString
	err := row.Scan(
		&userId,
		&username,
		&user.Password,
		&user.Salt,
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
		return nil, svrerr.ErrDBStorageFailed
	}

	return &user, nil
}

// GetUserByUserID Retrieves User from the db by user id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound, ErrParsingUserID
func (s *sqliteStorage) GetUserByUserID(uid string) (*entities.Account, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_USER_BY_ID, uid)

	var userId string
	var user entities.Account
	var username sql.NullString
	err := row.Scan(
		&userId,
		&username,
		&user.Password,
		&user.Salt,
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

// UpdateUserByID Updates User in the db by user id
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) UpdateUserByID(user *entities.Account) error {
	userName := NewNullString(user.Username)
	result, err := s.conn.Exec(
		ACCOUNT_UPDATE_USER_BY_ID,
		userName,
		user.Email,
		user.Password,
		user.Salt,
		user.UpdatedAt,
		user.ID.String(),
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
		logger.Error("user not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// GetUserList Retrieves User list from the db
// ERRORS: ErrDBRetrievingData
func (s *sqliteStorage) GetUserList(limit int, offset int) ([]*entities.Account, error) {

	rows, err := s.conn.Query(ACCOUNT_GET_USER_LIST, limit, offset)
	if err != nil {
		logger.Error("storage_error:", err)
		return nil, svrerr.ErrDBStorageFailed
	}
	defer rows.Close()

	var users []*entities.Account
	for rows.Next() {
		var userId string
		var user entities.Account
		var username sql.NullString
		err := rows.Scan(
			&userId,
			&username,
			&user.Email,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			logger.Error("storage_error:", err)
			return nil, svrerr.ErrDBStorageFailed
		}

		user.Username = username.String
		user.ID, err = entities.ParseUserId(userId)
		if err != nil {
			logger.Error("error parsing user id: ", err)
			return nil, svrerr.ErrDBStorageFailed
		}

		users = append(users, &user)
	}

	return users, nil
}

// GetTotalUsersCount Retrieves total number of users from the db
// ERRORS: ErrDBRetrievingData
func (s *sqliteStorage) GetTotalUsersCount() (int64, error) {

	row := s.conn.QueryRow(ACCOUNT_GET_TOTAL_USERS_COUNT)

	var count int64
	err := row.Scan(&count)
	if err != nil {
		logger.Error("storage_error:", err)
		return 0, svrerr.ErrDBStorageFailed
	}

	return count, nil
}

func (s *sqliteStorage) DeleteUserByID(uid string) error {
	result, err := s.conn.Exec(ACCOUNT_DELETE_USER_BY_ID, uid)
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("user not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}
