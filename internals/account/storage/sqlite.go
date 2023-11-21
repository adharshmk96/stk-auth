package storage

import (
	"database/sql"

	"github.com/adharshmk96/stk-auth/internals/account/domain"
)

type sqliteRepo struct {
	conn *sql.DB
}

func NewSqliteRepo(conn *sql.DB) domain.AccountStorage {
	return &sqliteRepo{
		conn: conn,
	}
}
