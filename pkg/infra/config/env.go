package config

import (
	"time"

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
	JWT_EXPIRATION_DURATION time.Duration
	JWT_SUBJECT             string
	JWT_ISSUER              string

	// Storage
	SQLITE_FILE string
}

var config = &Config{}

// Configurations are initialized from the environment variables using viper.
func init() {

	viper.SetDefault(ENV_SERVER_MODE, SERVER_DEV_MODE)

	viper.SetDefault(ENV_SESSION_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME)
	viper.SetDefault(ENV_JWT_SESSION_COOKIE_NAME, DEFAULT_SESSION_JWT_COOKIE_NAME)

	viper.SetDefault(ENV_JWT_EXPIRATION_DURATION, DEFAULT_JWT_EXPIRATION_DURATION)
	viper.SetDefault(ENV_JWT_ISSUER, DEFAULT_JWT_ISSUER)
	viper.SetDefault(ENV_JWT_SUBJECT, DEFAULT_JWT_SUBJECT)

	viper.SetDefault(ENV_SQLITE_FILE, DEFAULT_SQLITE_FILE)

	viper.AutomaticEnv()

	// Server
	config.SERVER_MODE = viper.GetString(ENV_SERVER_MODE)

	// Session
	config.SESSION_COOKIE_NAME = viper.GetString(ENV_SESSION_COOKIE_NAME)
	config.JWT_SESSION_COOKIE_NAME = viper.GetString(ENV_JWT_SESSION_COOKIE_NAME)

	// JWT
	config.JWT_EXPIRATION_DURATION = time.Minute * viper.GetDuration(ENV_JWT_EXPIRATION_DURATION)
	config.JWT_SUBJECT = viper.GetString(ENV_JWT_ISSUER)
	config.JWT_ISSUER = viper.GetString(ENV_JWT_SUBJECT)

	// Storage
	config.SQLITE_FILE = viper.GetString(ENV_SQLITE_FILE)

}

func GetConfig() *Config {
	return config
}
