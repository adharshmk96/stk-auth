package infra

import (
	"time"

	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/spf13/viper"
)

// server

// JWT

type Config struct {
	// Server
	SERVER_MODE string

	// Session
	SESSION_COOKIE_NAME     string
	JWT_SESSION_COOKIE_NAME string

	// JWT
	JWT_EDCA_PRIVATE_KEY_PATH string
	JWT_EDCA_PUBLIC_KEY_PATH  string
	JWT_EDCA_PUBLIC_KEY       string
	JWT_EDCA_PRIVATE_KEY      string
	JWT_EXPIRATION_DURATION   time.Duration
	JWT_SUBJECT               string
	JWT_ISSUER                string

	// Storage
	SQLITE_FILE_PATH    string
	MIGRATION_FILE_PATH string
}

var config = &Config{}

// Configurations are loaded from the environment variables using viper.
// callin this function will reLoad the config. (useful for testing)
// WARN: this will reload all the config.
func LoadConfigFromEnv() {

	viper.SetDefault(constants.ENV_SERVER_MODE, constants.SERVER_DEV_MODE)

	viper.SetDefault(constants.ENV_SESSION_COOKIE_NAME, constants.DEFAULT_SESSION_COOKIE_NAME)
	viper.SetDefault(constants.ENV_JWT_SESSION_COOKIE_NAME, constants.DEFAULT_SESSION_JWT_COOKIE_NAME)

	viper.SetDefault(constants.ENV_JWT_EXPIRATION_DURATION, constants.DEFAULT_JWT_EXPIRATION_DURATION)
	viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY_PATH, constants.DEFAULT_JWT_EDCA_PRIVATE_KEY_PATH)
	viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY_PATH, constants.DEFAULT_JWT_EDCA_PUBLIC_KEY_PATH)
	viper.SetDefault(constants.ENV_JWT_ISSUER, constants.DEFAULT_JWT_ISSUER)
	viper.SetDefault(constants.ENV_JWT_SUBJECT, constants.DEFAULT_JWT_SUBJECT)

	viper.SetDefault(constants.ENV_SQLITE_FILE, constants.DEFAULT_SQLITE_FILE)

	viper.AutomaticEnv()

	// TYPE: Server

	// SERVER_MODE: `SERVER_DEV_MODE` or `SERVER_PROD_MODE` (default `SERVER_DEV_MODE`)

	// TYPE: Session

	// SESSION_COOKIE_NAME: name of the session cookie (default `stk_session`)
	// JWT_SESSION_COOKIE_NAME: name of the jwt session cookie (default `stk_jwt_session`)

	// TYPE: JWT

	// JWT_EDCA_PRIVATE_KEY: private key for the jwt token (default `""`)
	// JWT_EDCA_PUBLIC_KEY: public key for the jwt token (default `""`)
	// JWT_EDCA_PRIVATE_KEY_PATH: path to the private key for the jwt token (default `./keys/private.pem`)
	// JWT_EDCA_PUBLIC_KEY_PATH: path to the public key for the jwt token (default `./keys/public.pem`)
	// JWT_EXPIRATION_DURATION: duration of the jwt token (default `1h`)
	// JWT_SUBJECT: subject of the jwt token (default `stk-auth`)
	// JWT_ISSUER: issuer of the jwt token (default `stk-auth`)

	// TYPE: Storage

	// SQLITE_FILE_PATH: sqlite file path (default `./db.sqlite`)

	// TYPE: Migration

	// MIGRATION_FILE_PATH: migration file path (default `./migrations`)

}

func GetConfig() *Config {
	return config
}

func init() {
	LoadConfigFromEnv()
}
