package sqlite

const (
	ACCOUNT_USER_TABLE_NAME = "auth_user_accounts"

	ACCOUNT_INSERT_USER_QUERY = "INSERT INTO " + ACCOUNT_USER_TABLE_NAME + " (id, username, password, salt, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"

	ACCOUNT_GET_USER_BY_ID       = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE id = ?"
	ACCOUNT_GET_USER_BY_EMAIL    = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE email = ?"
	ACCOUNT_GET_USER_BY_USERNAME = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE username = ?"
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
