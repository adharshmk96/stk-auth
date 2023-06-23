package sqlite

const (
	USER_TABLE_NAME = "auth_user_accounts"
)

const (
	INSERT_USER_QUERY = "INSERT INTO " + USER_TABLE_NAME + " (id, username, password, salt, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
)
