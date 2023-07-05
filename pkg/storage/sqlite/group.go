package sqlite

import (
	"database/sql"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveGroup Stores Group in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveGroup(group *entities.UserGroup) error {

	result, err := s.conn.Exec(
		ACCOUNT_INSERT_GROUP_QUERY,
		group.ID,
		group.Name,
		group.CreatedAt,
		group.UpdatedAt,
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

// UpdateGroupByID Updates Group in the db by group id
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) UpdateGroupByID(group *entities.UserGroup) error {
	result, err := s.conn.Exec(
		ACCOUNT_UPDATE_GROUP_QUERY,
		group.Name,
		group.UpdatedAt,
		group.ID,
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
		logger.Error("group not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// GetGroupByID Retrieves Group from the db by group id
// ERRORS: ErrDBRetrievingData, ErrDBEntryNotFound
func (s *sqliteStorage) GetGroupByID(groupId string) (*entities.UserGroup, error) {
	row := s.conn.QueryRow(ACCOUNT_RETRIEVE_GROUP_BY_ID_QUERY, groupId)

	var group entities.UserGroup
	err := row.Scan(
		&group.ID,
		&group.Name,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			logger.Error("record not found:", err)
			return nil, svrerr.ErrDBEntryNotFound
		}

		logger.Error("error retrieving group from database: ", err)
		return nil, svrerr.ErrDBStorageFailed
	}

	return &group, nil
}

// DeleteGroupByID Deletes Group from the db by group id
// ERRORS: ErrDBDeletingData, ErrDBEntryNotFound
func (s *sqliteStorage) DeleteGroupByID(groupId string) error {
	result, err := s.conn.Exec(
		ACCOUNT_DELETE_GROUP_QUERY,
		groupId,
	)
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	rows, err := result.RowsAffected()
	if rows == 0 {
		logger.Error("group not found")
		return svrerr.ErrDBEntryNotFound
	}
	if err != nil {
		logger.Error("storage_error:", err)
		return svrerr.ErrDBStorageFailed
	}

	return nil
}

// SaveGroupAssociation Stores Group Association in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveGroupAssociation(association *entities.UserGroupAssociation) error {
	result, err := s.conn.Exec(
		ACCOUNT_INSERT_GROUP_ASSOCIATION_QUERY,
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
func (s *sqliteStorage) GetGroupsByUserID(userID string) ([]*entities.UserGroup, error) {
	rows, err := s.conn.Query(ACCOUNT_RETRIEVE_GROUPS_BY_USER_ID_QUERY, userID)
	if err != nil {
		logger.Error("storage_error:", err)
		return nil, svrerr.ErrDBStorageFailed
	}
	defer rows.Close()

	groups := make([]*entities.UserGroup, 0)
	for rows.Next() {
		var group entities.UserGroup
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
		ACCOUNT_DELETE_GROUP_ASSOCIATION_QUERY,
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
