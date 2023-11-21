package storage

import "github.com/adharshmk96/stk/pkg/sqlBuilder"

const (
	ACCOUNT_TABLE = "account"
)

var (
	INSERT_ACCOUNT = sqlBuilder.NewSqlQuery().
			InsertInto(ACCOUNT_TABLE).
			Fields(
			"id",
			"username",
			"email",
			"first_name",
			"last_name",
			"password",
			"salt",
			"created_at",
			"updated_at",
		).
		Values("?", "?", "?", "?", "?", "?", "?", "?", "?").
		Build()

	GET_ACCOUNT_BY_EMAIL = sqlBuilder.NewSqlQuery().
				Select(
			"id",
			"username",
			"email",
			"first_name",
			"last_name",
			"password",
			"salt",
			"created_at",
			"updated_at",
		).
		From(ACCOUNT_TABLE).
		Where("email = ?").
		Build()
)
