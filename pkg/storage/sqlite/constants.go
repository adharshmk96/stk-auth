package sqlite

const (
	sqlitePath = "auth_database.db"
)

const (
	USER_TABLE_NAME = "auth_user_accounts"
)

const (
	INSERT_USER_QUERY = "INSERT INTO " + USER_TABLE_NAME + " (id, username, password, salt, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	GET_USER_BY_ID    = "SELECT id, username, password, salt, email, created_at, updated_at FROM " + USER_TABLE_NAME + " WHERE id = ?"
)
