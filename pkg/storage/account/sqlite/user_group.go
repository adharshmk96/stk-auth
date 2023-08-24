package sqlite

import (
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveGroupAssociation Stores Group Association in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveGroupAssociation(association *ds.AccountGroupAssociation) error {
	result, err := s.conn.Exec(
		Q_InsertAccountGroupAssociation,
		association.AccountID.String(),
		association.GroupID,
		association.CreatedAt,
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

// GetGroupsByAccountID Retrieves Groups from the db by account id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound
func (s *sqliteStorage) GetGroupsByAccountID(accountID string) ([]*ds.Group, error) {
	rows, err := s.conn.Query(Q_GetGroupsByAccountID, accountID)
	if err != nil {
		logger.Error("storage_error:", err)
		return nil, svrerr.ErrDBStorageFailed
	}
	defer rows.Close()

	groups := make([]*ds.Group, 0)
	for rows.Next() {
		var group ds.Group
		err := rows.Scan(
			&group.ID,
			&group.Name,
			&group.CreatedAt,
			&group.UpdatedAt,
		)
		if err != nil {
			logger.Error("storage_error:", err)
			return nil, svrerr.ErrDBStorageFailed
		}
		groups = append(groups, &group)
	}

	if len(groups) == 0 {
		logger.Error("record not found")
		return nil, svrerr.ErrDBEntryNotFound
	}

	return groups, nil
}

// DeleteAccountGroupAssociation Deletes Group Association from the db by account id and group id
// ERRORS: ErrDBDeletingData, ErrDBEntryNotFound
func (s *sqliteStorage) DeleteAccountGroupAssociation(accountID string, groupID string) error {
	result, err := s.conn.Exec(
		Q_DeleteAccountGroupAssociation,
		accountID,
		groupID,
	)
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("group association not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// CheckAccountGroupAssociation Retrieves Group Association from the db by account id and group id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound
func (s *sqliteStorage) CheckAccountGroupAssociation(accountID string, groupID string) (bool, error) {
	row := s.conn.QueryRow(Q_CheckAccountGroupAssociation, accountID, groupID)

	var rows int
	row.Scan(&rows)

	if rows == 1 {
		return true, nil
	}

	return false, nil
}
