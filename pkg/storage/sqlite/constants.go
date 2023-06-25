package sqlite

const (
	sqlitePath = "auth_database.db"
)

const (
	ACCOUNT_USER_TABLE_NAME   = "auth_user_accounts"
	ACCOUNT_INSERT_USER_QUERY = "INSERT INTO " + ACCOUNT_USER_TABLE_NAME + " (id, username, password, salt, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	ACCOUNT_GET_USER_BY_ID    = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + ACCOUNT_USER_TABLE_NAME + " WHERE id = ?"
)
