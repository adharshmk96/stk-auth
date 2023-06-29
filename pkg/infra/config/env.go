package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// FROM ENVIRONMENT

var (
	// Server
	SERVER_MODE string

	// Session
	SESSION_COOKIE_NAME     string
	JWT_SESSION_COOKIE_NAME string

	// JWT
	JWT_EXPIRATION_DURATION time.Duration

	// Storage
	SQLITE_FILE string
)

// Configurations are initialized from the environment variables using viper.
func init() {

	viper.SetDefault(ENV_SERVER_MODE, SERVER_DEV_MODE)

	viper.SetDefault(ENV_SESSION_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME)
	viper.SetDefault(ENV_JWT_SESSION_COOKIE_NAME, DEFAULT_SESSION_JWT_COOKIE_NAME)

	viper.SetDefault(ENV_JWT_EXPIRATION_DURATION, DEFAULT_JWT_EXPIRATION_DURATION)

	viper.SetDefault(ENV_SQLITE_FILE, DEFAULT_SQLITE_FILE)

	viper.AutomaticEnv()

	// Server
	SERVER_MODE = viper.GetString(ENV_SERVER_MODE)

	// Session
	SESSION_COOKIE_NAME = viper.GetString(ENV_SESSION_COOKIE_NAME)
	JWT_SESSION_COOKIE_NAME = viper.GetString(ENV_JWT_SESSION_COOKIE_NAME)

	// JWT
	JWT_EXPIRATION_DURATION = time.Minute * viper.GetDuration(ENV_JWT_EXPIRATION_DURATION)

	// Storage
	SQLITE_FILE = viper.GetString(ENV_SQLITE_FILE)

	fmt.Println("JWT_EXPIRATION_DURATION: ", JWT_EXPIRATION_DURATION)

}
