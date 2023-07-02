package constants

// constant values
const (
	// server
	SERVER_DEV_MODE     = "dev"
	SERVER_STAGING_MODE = "stage"
	SERVER_PROD_MODE    = "prod"
)

// #ENVIRONMENT VARIABLES

// config name
const (
	// Server
	ENV_SERVER_MODE   = "server.mode"
	ENV_SERVER_DOMAIN = "server.domain"

	// Session
	ENV_SESSION_COOKIE_NAME     = "server.cookie.session.name"
	ENV_JWT_SESSION_COOKIE_NAME = "server.cookie.jwt_session.name"

	// Storage
	ENV_SQLITE_FILE = "server.storage.sqlite.file"

	ENV_MIGRATOR_DIR = "migrator.workdir"

	// JWT
	ENV_JWT_ISSUER  = "server.jwt.issuer"
	ENV_JWT_SUBJECT = "server.jwt.subject"

	ENV_JWT_EXPIRATION_DURATION   = "server.jwt.expiry"
	ENV_JWT_EDCA_PRIVATE_KEY      = "server.jwt.private_key"
	ENV_JWT_EDCA_PUBLIC_KEY       = "server.jwt.public_key"
	ENV_JWT_EDCA_PRIVATE_KEY_PATH = "server.jwt.private_key_path"
	ENV_JWT_EDCA_PUBLIC_KEY_PATH  = "server.jwt.public_key_path"
)

// config defaults
const (
	DEFAULT_SERVER_DOMAIN = "localhost"
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
