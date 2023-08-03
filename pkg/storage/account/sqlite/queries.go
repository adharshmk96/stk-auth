package sqlite

import (
	"github.com/adharshmk96/stk/pkg/sqlBuilder"
)

const (
	TableAccount                 = "auth_account_accounts"
	TableSession                 = "auth_account_sessions"
	TableGroup                   = "auth_account_groups"
	TableAccountGroupAssociation = "auth_account_group_association"
)

var (
	Q_InsertAccountQuery   = ""
	Q_GetAccountByID       = ""
	Q_GetAccountByEmail    = ""
	Q_GetAccountByUsername = ""
	Q_UpdateAccountByID    = ""
	Q_DeleteAccountByID    = ""
)

var (
	Q_InsertSession     = ""
	Q_GetSessionByID    = ""
	Q_InvalidateSession = ""
)

var (
	Q_GetAccountBySessionID = ""
)

var (
	Q_InsertGroup  = ""
	Q_UpdateGroup  = ""
	Q_DeleteGroup  = ""
	Q_GetGroupByID = ""

	Q_InsertAccountGroupAssociation = ""
	Q_GetGroupsByAccountID          = ""
	Q_CheckAccountGroupAssociation  = ""
	Q_DeleteAccountGroupAssociation = ""
)

var (
	Q_GetAccountList       = ""
	Q_GetTotalAccountCount = ""
)

func init() {
	query := sqlBuilder.NewSqlQuery()
	Q_InsertAccountQuery = query.InsertInto(TableAccount).
		Fields("id", "username", "password", "salt", "email", "created_at", "updated_at").
		Values("?", "?", "?", "?", "?", "?", "?").
		Build()

	Q_GetAccountByID = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(TableAccount).
		Where("id = ?").
		Build()

	Q_GetAccountByEmail = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(TableAccount).
		Where("email = ?").
		Build()

	Q_GetAccountByUsername = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(TableAccount).
		Where("username = ?").
		Build()

	Q_UpdateAccountByID = query.Update(TableAccount).
		Set("username=?", "email=?", "password=?", "salt=?", "updated_at=?").
		Where("id = ?").
		Build()

	Q_DeleteAccountByID = query.DeleteFrom(TableAccount).
		Where("id = ?").
		Build()

	Q_InsertSession = query.InsertInto(TableSession).
		Fields("account_id", "session_id", "created_at", "updated_at", "valid").
		Values("?", "?", "?", "?", "?").
		Build()

	Q_GetSessionByID = query.Select("account_id", "session_id", "created_at", "updated_at", "valid").
		From(TableSession).
		Where("session_id = ?", "valid=1").
		Build()

	Q_InvalidateSession = query.Update(TableSession).
		Set("valid=0").
		Where("session_id = ?").
		Build()

	Q_InsertGroup = query.InsertInto(TableGroup).
		Fields("id", "name", "created_at", "updated_at").
		Values("?", "?", "?", "?").
		Build()

	Q_UpdateGroup = query.Update(TableGroup).
		Set("name=?", "updated_at=?").
		Where("id = ?").
		Build()

	Q_DeleteGroup = query.DeleteFrom(TableGroup).
		Where("id = ?").
		Build()

	Q_GetGroupByID = query.Select("id", "name", "created_at", "updated_at").
		From(TableGroup).
		Where("id = ?").
		Build()

	Q_InsertAccountGroupAssociation = query.InsertInto(TableAccountGroupAssociation).
		Fields("account_id", "group_id", "created_at").
		Values("?", "?", "?").
		Build()

	Q_DeleteAccountGroupAssociation = query.DeleteFrom(TableAccountGroupAssociation).
		Where("account_id = ?", "group_id=?").
		Build()

	Q_GetGroupsByAccountID = query.Select("g.id", "g.name", "g.created_at", "g.updated_at").
		From(TableGroup + " g").
		Join(TableAccountGroupAssociation + " ga").
		On("g.id = ga.group_id").
		Where("ga.account_id = ?").
		Build()

	Q_CheckAccountGroupAssociation = query.Select("count(id)").
		From(TableAccountGroupAssociation).
		Where("account_id = ?", "group_id=?").
		Build()

	subQuery := sqlBuilder.NewSqlQuery()
	subQueryAccount := subQuery.Select("account_id").
		From(TableSession).
		Where("session_id = ?", "valid=1").
		Build()

	Q_GetAccountBySessionID = query.Select("id", "username", "email", "created_at", "updated_at").
		From(TableAccount).
		Where("id = (" + subQueryAccount + ") ").
		Build()

	Q_GetAccountList = query.Select("id", "username", "email", "created_at", "updated_at").
		From(TableAccount).
		Limit("?").
		Offset("?").
		Build()

	Q_GetTotalAccountCount = query.Select("count(id)").
		From(TableAccount).
		Build()
}
