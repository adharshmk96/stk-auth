package sqlite

import (
	"database/sql"

	"github.com/adharshmk96/stk-auth/pkg/entities"
)

type sqliteStorage struct {
	conn *sql.DB
}

func NewAccountStorage(conn *sql.DB) entities.UserManagementStore {
	return &sqliteStorage{
		conn: conn,
	}
}
