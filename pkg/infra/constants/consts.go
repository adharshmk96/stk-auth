package constants

// constant values
const (
	// server
	SERVER_DEV_MODE  = "SERVER_DEV_MODE"
	SERVER_PROD_MODE = "SERVER_PROD_MODE"
)

// #ENVIRONMENT VARIABLES

// config name
const (
	// Server
	ENV_SERVER_MODE = "SERVER_MODE"

	// Session
	ENV_SESSION_COOKIE_NAME     = "SESSION_COOKIE_NAME"
	ENV_JWT_SESSION_COOKIE_NAME = "JWT_SESSION_COOKIE_NAME"

	// Storage
	ENV_SQLITE_FILE = "SQLITE_FILE"

	// JWT
	ENV_JWT_ISSUER  = "JWT_ISSUER"
	ENV_JWT_SUBJECT = "JWT_SUBJECT"

	ENV_JWT_EXPIRATION_DURATION   = "JWT_EXPIRATION_DURATION"
	ENV_JWT_EDCA_PRIVATE_KEY      = "JWT_EDCA_PRIVATE_KEY"
	ENV_JWT_EDCA_PUBLIC_KEY       = "JWT_EDCA_PUBLIC_KEY"
	ENV_JWT_EDCA_PRIVATE_KEY_PATH = "JWT_EDCA_PRIVATE_KEY_PATH"
	ENV_JWT_EDCA_PUBLIC_KEY_PATH  = "JWT_EDCA_PUBLIC_KEY_PATH"
)

// config defaults
const (
	// Session
	DEFAULT_SESSION_COOKIE_NAME     = "stk_session"
	DEFAULT_SESSION_JWT_COOKIE_NAME = "stk_session_token"

	// Storage
	DEFAULT_SQLITE_FILE = "auth_database.db"

	// JWT
	DEFAULT_JWT_EXPIRATION_DURATION   = 1440
	DEFAULT_JWT_EDCA_PRIVATE_KEY_PATH = ".keys/private_key.pem"
	DEFAULT_JWT_EDCA_PUBLIC_KEY_PATH  = ".keys/public_key.pem"
	DEFAULT_JWT_ISSUER                = "stk-auth-server"
	DEFAULT_JWT_SUBJECT               = "authentication"
)