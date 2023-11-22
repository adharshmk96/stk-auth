package storage

import "github.com/adharshmk96/stk/pkg/sqlBuilder"

const (
	SESSION_TABLE = "session"
)

var (
	INSERT_SESSION = sqlBuilder.NewSqlQuery().
			InsertInto(SESSION_TABLE).
			Fields("id", "account_id", "active", "created_at").
			Values("?", "?", "?", "?").
			Build()

	GET_SESSION_BY_ID = sqlBuilder.NewSqlQuery().
				Select("id", "account_id", "active", "created_at").
				From(SESSION_TABLE).
				Where("id = ?", "active = true").
				Build()

	UPDATE_SESSION = sqlBuilder.NewSqlQuery().
			Update(SESSION_TABLE).
			Set("active = ?").
			Where("id = ?").
			Build()

	GET_ACCOUNT_BY_SESSION_ID = sqlBuilder.NewSqlQuery().
					Select(
			"a.id",
			"a.username",
			"a.email",
			"a.password",
			"a.salt",
			"a.created_at",
			"a.updated_at",
		).
		From(SESSION_TABLE+" s").
		Join(ACCOUNT_TABLE+" a").
		On("s.account_id = a.id").
		Where("s.id = ?", "s.active = true").
		Build()

	DEACTIVATE_SESSION = sqlBuilder.NewSqlQuery().
				Update(SESSION_TABLE).
				Set("active = false").
				Where("id = ?").
				Build()
)
