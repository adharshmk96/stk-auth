package sqlite

import (
	"github.com/adharshmk96/stk/pkg/sqlBuilder"
)

const (
	TableUser                 = "auth_user_accounts"
	TableSession              = "auth_user_sessions"
	TableGroup                = "auth_user_groups"
	TableUserGroupAssociation = "auth_user_group_association"
)

var (
	Q_InsertUserQuery   = ""
	Q_GetUserByID       = ""
	Q_GetUserByEmail    = ""
	Q_GetUserByUsername = ""
	Q_UpdateUserByID    = ""
	Q_DeleteUserByID    = ""
)

var (
	Q_InsertSession     = ""
	Q_GetSessionByID    = ""
	Q_InvalidateSession = ""
)

var (
	Q_GetUserBySessionID = ""
)

var (
	Q_InsertGroup  = ""
	Q_UpdateGroup  = ""
	Q_DeleteGroup  = ""
	Q_GetGroupByID = ""

	Q_InsertUserGroupAssociation = ""
	Q_GetGroupsByUserID          = ""
	Q_CheckUserGroupAssociation  = ""
	Q_DeleteUserGroupAssociation = ""
)

var (
	Q_GetUserList       = ""
	Q_GetTotalUserCount = ""
)

func init() {
	query := sqlBuilder.NewSqlQuery()
	Q_InsertUserQuery = query.InsertInto(TableUser).
		Fields("id", "username", "password", "salt", "email", "created_at", "updated_at").
		Values("?", "?", "?", "?", "?", "?", "?").
		Build()

	Q_GetUserByID = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(TableUser).
		Where("id = ?").
		Build()

	Q_GetUserByEmail = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(TableUser).
		Where("email = ?").
		Build()

	Q_GetUserByUsername = query.Select("id", "username", "password", "salt", "email", "created_at", "updated_at").
		From(TableUser).
		Where("username = ?").
		Build()

	Q_UpdateUserByID = query.Update(TableUser).
		Set("username=?", "email=?", "password=?", "salt=?", "updated_at=?").
		Where("id = ?").
		Build()

	Q_DeleteUserByID = query.DeleteFrom(TableUser).
		Where("id = ?").
		Build()

	Q_InsertSession = query.InsertInto(TableSession).
		Fields("user_id", "session_id", "created_at", "updated_at", "valid").
		Values("?", "?", "?", "?", "?").
		Build()

	Q_GetSessionByID = query.Select("user_id", "session_id", "created_at", "updated_at", "valid").
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

	Q_InsertUserGroupAssociation = query.InsertInto(TableUserGroupAssociation).
		Fields("user_id", "group_id", "created_at").
		Values("?", "?", "?").
		Build()

	Q_DeleteUserGroupAssociation = query.DeleteFrom(TableUserGroupAssociation).
		Where("user_id = ?", "group_id=?").
		Build()

	Q_GetGroupsByUserID = query.Select("g.id", "g.name", "g.created_at", "g.updated_at").
		From(TableGroup + " g").
		Join(TableUserGroupAssociation + " ga").
		On("g.id = ga.group_id").
		Where("ga.user_id = ?").
		Build()

	Q_CheckUserGroupAssociation = query.Select("count(id)").
		From(TableUserGroupAssociation).
		Where("user_id = ?", "group_id=?").
		Build()

	subQuery := sqlBuilder.NewSqlQuery()
	subQueryUser := subQuery.Select("user_id").
		From(TableSession).
		Where("session_id = ?", "valid=1").
		Build()

	Q_GetUserBySessionID = query.Select("id", "username", "email", "created_at", "updated_at").
		From(TableUser).
		Where("id = (" + subQueryUser + ") ").
		Build()

	Q_GetUserList = query.Select("id", "username", "email", "created_at", "updated_at").
		From(TableUser).
		Limit("?").
		Offset("?").
		Build()

	Q_GetTotalUserCount = query.Select("count(id)").
		From(TableUser).
		Build()
}
