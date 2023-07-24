package sqlite

import (
	"github.com/adharshmk96/stk/pkg/sqlBuilder"
)

const (
	AccountUserTableName                 = "auth_user_accounts"
	AccountSessionTableName              = "auth_user_sessions"
	ACCOUNT_GROUP_TABLE_NAME             = "auth_user_groups"
	ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME = "auth_user_group_associations"
)

var (
	ACCOUNT_INSERT_USER_QUERY    = ""
	ACCOUNT_GET_USER_BY_ID       = ""
	ACCOUNT_GET_USER_BY_EMAIL    = ""
	ACCOUNT_GET_USER_BY_USERNAME = ""
	ACCOUNT_UPDATE_USER_BY_ID    = ""
	ACCOUNT_DELETE_USER_BY_ID    = ""
)

var (
	ACCOUNT_INSERT_SESSION_QUERY   = ""
	ACCOUNT_RETRIEVE_SESSION_BY_ID = ""
	ACCOUNT_INVALIDATE_SESSION_ID  = ""
)

var (
	ACCOUNT_RETRIEVE_USER_BY_SESSION_ID = ""
)

var (
	ACCOUNT_INSERT_GROUP_QUERY                 = ""
	ACCOUNT_UPDATE_GROUP_QUERY                 = ""
	ACCOUNT_DELETE_GROUP_QUERY                 = ""
	ACCOUNT_RETRIEVE_GROUP_BY_ID_QUERY         = ""
	ACCOUNT_INSERT_GROUP_ASSOCIATION_QUERY     = ""
	ACCOUNT_DELETE_GROUP_ASSOCIATION_QUERY     = ""
	ACCOUNT_RETRIEVE_GROUPS_BY_USER_ID_QUERY   = ""
	ACCOUNT_CHECK_USER_GROUP_ASSOCIATION_QUERY = ""
)

var (
	ACCOUNT_GET_USER_LIST         = ""
	ACCOUNT_GET_TOTAL_USERS_COUNT = ""
)

func init() {
	query := sqlBuilder.NewSqlQuery()
	ACCOUNT_INSERT_USER_QUERY = query.InsertInto(AccountUserTableName).
		Fields("id", "username", "password", "salt", "email", "created_at", "updated_at").
		Values("?", "?", "?", "?", "?", "?", "?").
		Build()

	ACCOUNT_GET_USER_BY_ID = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(AccountUserTableName).
		Where("id = ?").
		Build()

	ACCOUNT_GET_USER_BY_EMAIL = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(AccountUserTableName).
		Where("email = ?").
		Build()

	ACCOUNT_GET_USER_BY_USERNAME = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(AccountUserTableName).
		Where("username = ?").
		Build()

	ACCOUNT_UPDATE_USER_BY_ID = query.Update(AccountUserTableName).
		Set("username=?", "email=?", "password=?", "salt=?", "updated_at=?").
		Where("id = ?").
		Build()

	ACCOUNT_DELETE_USER_BY_ID = query.DeleteFrom(AccountUserTableName).
		Where("id = ?").
		Build()

	ACCOUNT_INSERT_SESSION_QUERY = query.InsertInto(AccountSessionTableName).
		Fields("user_id", "session_id", "created_at", "updated_at", "valid").
		Values("?", "?", "?", "?", "?").
		Build()

	ACCOUNT_RETRIEVE_SESSION_BY_ID = query.Select("user_id", "session_id", "created_at", "updated_at", "valid").
		From(AccountSessionTableName).
		Where("session_id = ?", "valid=1").
		Build()

	ACCOUNT_INVALIDATE_SESSION_ID = query.Update(AccountSessionTableName).
		Set("valid=0").
		Where("session_id = ?").
		Build()

	ACCOUNT_INSERT_GROUP_QUERY = query.InsertInto(ACCOUNT_GROUP_TABLE_NAME).
		Fields("id", "name", "created_at", "updated_at").
		Values("?", "?", "?", "?").
		Build()

	ACCOUNT_UPDATE_GROUP_QUERY = query.Update(ACCOUNT_GROUP_TABLE_NAME).
		Set("name=?", "updated_at=?").
		Where("id = ?").
		Build()

	ACCOUNT_DELETE_GROUP_QUERY = query.DeleteFrom(ACCOUNT_GROUP_TABLE_NAME).
		Where("id = ?").
		Build()

	ACCOUNT_RETRIEVE_GROUP_BY_ID_QUERY = query.Select("id", "name", "created_at", "updated_at").
		From(ACCOUNT_GROUP_TABLE_NAME).
		Where("id = ?").
		Build()

	ACCOUNT_INSERT_GROUP_ASSOCIATION_QUERY = query.InsertInto(ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME).
		Fields("user_id", "group_id", "created_at").
		Values("?", "?", "?").
		Build()

	ACCOUNT_DELETE_GROUP_ASSOCIATION_QUERY = query.DeleteFrom(ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME).
		Where("user_id = ?", "group_id=?").
		Build()

	ACCOUNT_RETRIEVE_GROUPS_BY_USER_ID_QUERY = query.Select("g.id", "g.name", "g.created_at", "g.updated_at").
		From(ACCOUNT_GROUP_TABLE_NAME + " g").
		Join(ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME + " ga").
		On("g.id = ga.group_id").
		Where("ga.user_id = ?").
		Build()

	ACCOUNT_CHECK_USER_GROUP_ASSOCIATION_QUERY = query.Select("count(id)").
		From(ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME).
		Where("user_id = ?", "group_id=?").
		Build()

	subQuery := sqlBuilder.NewSqlQuery()
	subQueryUser := subQuery.Select("user_id").
		From(AccountSessionTableName).
		Where("session_id = ?", "valid=1").
		Build()

	ACCOUNT_RETRIEVE_USER_BY_SESSION_ID = query.Select("id", "username", "email", "created_at", "updated_at").
		From(AccountUserTableName).
		Where("id = (" + subQueryUser + ") ").
		Build()

	ACCOUNT_GET_USER_LIST = query.Select("id", "username", "email", "created_at", "updated_at").
		From(AccountUserTableName).
		Limit("?").
		Offset("?").
		Build()

	ACCOUNT_GET_TOTAL_USERS_COUNT = query.Select("count(id)").
		From(AccountUserTableName).
		Build()
}
