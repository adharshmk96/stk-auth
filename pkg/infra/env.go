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
	SQLITE_FILE_PATH string
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
	viper.SetDefault(constants.ENV_JWT_ISSUER, constants.DEFAULT_JWT_ISSUER)
	viper.SetDefault(constants.ENV_JWT_SUBJECT, constants.DEFAULT_JWT_SUBJECT)

	viper.SetDefault(constants.ENV_SQLITE_FILE, constants.DEFAULT_SQLITE_FILE)

	viper.AutomaticEnv()

	// Server
	config.SERVER_MODE = viper.GetString(constants.ENV_SERVER_MODE)

	// Session
	config.SESSION_COOKIE_NAME = viper.GetString(constants.ENV_SESSION_COOKIE_NAME)
	config.JWT_SESSION_COOKIE_NAME = viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME)

	// JWT
	config.JWT_EDCA_PRIVATE_KEY = viper.GetString(constants.ENV_JWT_EDCA_PRIVATE_KEY)
	config.JWT_EDCA_PUBLIC_KEY = viper.GetString(constants.ENV_JWT_EDCA_PUBLIC_KEY)
	config.JWT_EDCA_PRIVATE_KEY_PATH = viper.GetString(constants.ENV_JWT_EDCA_PRIVATE_KEY_PATH)
	config.JWT_EDCA_PUBLIC_KEY_PATH = viper.GetString(constants.ENV_JWT_EDCA_PUBLIC_KEY_PATH)
	config.JWT_EXPIRATION_DURATION = time.Minute * viper.GetDuration(constants.ENV_JWT_EXPIRATION_DURATION)
	config.JWT_SUBJECT = viper.GetString(constants.ENV_JWT_ISSUER)
	config.JWT_ISSUER = viper.GetString(constants.ENV_JWT_SUBJECT)

	// Storage
	config.SQLITE_FILE_PATH = viper.GetString(constants.ENV_SQLITE_FILE)

}

func GetConfig() *Config {
	return config
}

func init() {
	LoadConfigFromEnv()
}
