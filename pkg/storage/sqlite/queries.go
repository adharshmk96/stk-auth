package sqlite

const (
	ACCOUNT_USER_TABLE_NAME = "auth_user_accounts"

	ACCOUNT_INSERT_USER_QUERY = "INSERT INTO " + ACCOUNT_USER_TABLE_NAME + " (id, username, password, salt, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"

	ACCOUNT_GET_USER_BY_ID       = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE id = ?"
	ACCOUNT_GET_USER_BY_EMAIL    = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE email = ?"
	ACCOUNT_GET_USER_BY_USERNAME = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE username = ?"

	ACCOUNT_UPDATE_USER_BY_ID = "UPDATE " + ACCOUNT_USER_TABLE_NAME + " SET username = ?, email = ?, password = ?, salt = ?, updated_at = ? WHERE id = ?"
)

const (
	ACCOUNT_SESSION_TABLE_NAME   = "auth_user_sessions"
	ACCOUNT_INSERT_SESSION_QUERY = "INSERT INTO " + ACCOUNT_SESSION_TABLE_NAME + " (user_id, session_id, created_at , updated_at , valid ) VALUES (?, ?, ?, ?, ?)"

	ACCOUNT_RETRIEVE_SESSION_BY_ID = "SELECT user_id, session_id, created_at , updated_at , valid FROM " + ACCOUNT_SESSION_TABLE_NAME + " WHERE session_id = ? and valid = 1"
	ACCOUNT_INVALIDATE_SESSION_ID  = "UPDATE " + ACCOUNT_SESSION_TABLE_NAME + " SET valid = 0 WHERE session_id = ?"
)

const (
	ACCOUNT_RETRIEVE_USER_BY_SESSION_ID = "SELECT id, username, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE id = (SELECT user_id FROM " + ACCOUNT_SESSION_TABLE_NAME + " WHERE session_id = ? and valid = 1)"
)

const (
	ACCOUNT_GROUP_TABLE_NAME             = "auth_user_groups"
	ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME = "auth_user_group_associations"

	ACCOUNT_INSERT_GROUP_QUERY         = "INSERT INTO " + ACCOUNT_GROUP_TABLE_NAME + " (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)"
	ACCOUNT_UPDATE_GROUP_QUERY         = "UPDATE " + ACCOUNT_GROUP_TABLE_NAME + " SET name = ?, updated_at = ? WHERE id = ?"
	ACCOUNT_DELETE_GROUP_QUERY         = "DELETE FROM " + ACCOUNT_GROUP_TABLE_NAME + " WHERE id = ?"
	ACCOUNT_RETRIEVE_GROUP_BY_ID_QUERY = "SELECT id, name, created_at, updated_at FROM " + ACCOUNT_GROUP_TABLE_NAME + " WHERE id = ?"

	ACCOUNT_INSERT_GROUP_ASSOCIATION_QUERY   = "INSERT INTO " + ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME + " (user_id, group_id, created_at) VALUES (?, ?, ?)"
	ACCOUNT_DELETE_GROUP_ASSOCIATION_QUERY   = "DELETE FROM " + ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME + " WHERE user_id = ? AND group_id = ?"
	ACCOUNT_RETRIEVE_GROUPS_BY_USER_ID_QUERY = "SELECT g.id, g.name, g.created_at, g.updated_at FROM " + ACCOUNT_GROUP_TABLE_NAME + " g INNER JOIN " + ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME + " ga ON g.id = ga.group_id WHERE ga.user_id = ?"

	ACCOUNT_CHECK_USER_GROUP_ASSOCIATION_QUERY = "SELECT count(id) FROM " + ACCOUNT_GROUP_ASSOCIATION_TABLE_NAME + " WHERE user_id = ? AND group_id = ?"
)
