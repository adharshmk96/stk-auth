package sqlite

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

// SaveGroup Stores Group in the db
// ERRORS: ErrDBStoringData, ErrDBDuplicateEntry
func (s *sqliteStorage) SaveGroup(group *entities.Group) error {

	result, err := s.conn.Exec(
		Q_InsertGroup,
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

// UpdateGroup Updates Group in the db by group id
// ERRORS: ErrDBUpdatingData, ErrDBEntryNotFound
func (s *sqliteStorage) UpdateGroup(group *entities.Group) error {
	result, err := s.conn.Exec(
		Q_UpdateGroup,
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
func (s *sqliteStorage) GetGroupByID(groupId string) (*entities.Group, error) {
	row := s.conn.QueryRow(Q_GetGroupByID, groupId)

	var group entities.Group
	err := row.Scan(
		&group.ID,
		&group.Name,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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
		Q_DeleteGroup,
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
