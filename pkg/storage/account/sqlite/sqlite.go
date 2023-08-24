package sqlite

import (
	"database/sql"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra"
)

var logger = infra.GetLogger()

func NewNullString(s string) sql.NullString {
	if len(s) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

type sqliteStorage struct {
	conn *sql.DB
}

func NewAccountStorage(conn *sql.DB) entities.AuthenticationStore {
	return &sqliteStorage{
		conn: conn,
	}
}
