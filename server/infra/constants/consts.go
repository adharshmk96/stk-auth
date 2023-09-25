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
	ENV_SESSION_COOKIE_NAME           = "server.cookie.session.name"
	ENV_JWT_ACCESS_TOKEN_COOKIE_NAME  = "server.cookie.jwt_access.name"
	ENV_JWT_REFRESH_TOKEN_COOKIE_NAME = "server.cookie.jwt_refresh.name"

	// Storage
	ENV_SQLITE_FILE = "server.storage.sqlite.file"

	ENV_MIGRATOR_DIR = "migrator.workdir"

	// JWT
	ENV_JWT_ISSUER  = "server.jwt.issuer"
	ENV_JWT_SUBJECT = "server.jwt.subject"

	ENV_ACCESS_JWT_EXPIRATION_DURATION  = "server.jwt.access_expiry"
	ENV_REFRESH_JWT_EXPIRATION_DURATION = "server.jwt.refresh_expiry"
	ENV_JWT_EDCA_PRIVATE_KEY            = "server.jwt.private_key"
	ENV_JWT_EDCA_PUBLIC_KEY             = "server.jwt.public_key"
	ENV_JWT_EDCA_PRIVATE_KEY_PATH       = "server.jwt.private_key_path"
	ENV_JWT_EDCA_PUBLIC_KEY_PATH        = "server.jwt.public_key_path"

	ENV_ROOT_ADMIN_USERNAME = "server.root_admin.username"
	ENV_ROOT_ADMIN_PASSWORD = "server.root_admin.password"
	ENV_ROOT_ADMIN_EMAIL    = "server.root_admin.email"

	// Email
	ENV_SERVER_EMAIL_FROM      = "server.email.from"
	ENV_SERVER_EMAIL_HOST      = "server.email.host"
	ENV_SERVER_EMAIL_PORT      = "server.email.port"
	ENV_SERVER_EMAIL_USER      = "server.email.user"
	ENV_SERVER_EMAIL_PASS      = "server.email.pass"
	ENV_SERVER_EMAIL_RESET_URL = "server.email.reset_url"
)
