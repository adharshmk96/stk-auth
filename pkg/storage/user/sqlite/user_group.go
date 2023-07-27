package sqlite

import (
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveGroupAssociation Stores Group Association in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveGroupAssociation(association *entities.UserGroupAssociation) error {
	result, err := s.conn.Exec(
		Q_InsertUserGroupAssociation,
		association.UserID.String(),
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

// GetGroupsByUserID Retrieves Groups from the db by user id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound
func (s *sqliteStorage) GetGroupsByUserID(userID string) ([]*entities.Group, error) {
	rows, err := s.conn.Query(Q_GetGroupsByUserID, userID)
	if err != nil {
		logger.Error("storage_error:", err)
		return nil, svrerr.ErrDBStorageFailed
	}
	defer rows.Close()

	groups := make([]*entities.Group, 0)
	for rows.Next() {
		var group entities.Group
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

// DeleteUserGroupAssociation Deletes Group Association from the db by user id and group id
// ERRORS: ErrDBDeletingData, ErrDBEntryNotFound
func (s *sqliteStorage) DeleteUserGroupAssociation(userID string, groupID string) error {
	result, err := s.conn.Exec(
		Q_DeleteUserGroupAssociation,
		userID,
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

// CheckUserGroupAssociation Retrieves Group Association from the db by user id and group id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound
func (s *sqliteStorage) CheckUserGroupAssociation(userID string, groupID string) (bool, error) {
	row := s.conn.QueryRow(Q_CheckUserGroupAssociation, userID, groupID)

	var rows int
	row.Scan(&rows)

	if rows == 1 {
		return true, nil
	}

	return false, nil
}
