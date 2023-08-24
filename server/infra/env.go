package infra

import (
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/spf13/viper"
)

// Configurations are loaded from the environment variables using viper.
// callin this function will reLoad the config. (useful for testing)
// WARN: this will reload all the config.
func LoadDefaultConfig() {

	viper.SetDefault(constants.ENV_SERVER_MODE, constants.SERVER_DEV_MODE)
	viper.SetDefault(constants.ENV_SERVER_DOMAIN, "localhost")

	viper.SetDefault(constants.ENV_SESSION_COOKIE_NAME, "stk_session")
	viper.SetDefault(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME, "stk_access_token")
	viper.SetDefault(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME, "stk_refresh_token")

	viper.SetDefault(constants.ENV_ACCESS_JWT_EXPIRATION_DURATION, 1440)
	viper.SetDefault(constants.ENV_REFRESH_JWT_EXPIRATION_DURATION, 1440*30)
	viper.SetDefault(constants.ENV_JWT_EDCA_PRIVATE_KEY_PATH, ".keys/private_key.pem")
	viper.SetDefault(constants.ENV_JWT_EDCA_PUBLIC_KEY_PATH, ".keys/public_key.pem")
	viper.SetDefault(constants.ENV_JWT_ISSUER, "stk-auth-server")
	viper.SetDefault(constants.ENV_JWT_SUBJECT, "authentication")

	viper.SetDefault(constants.ENV_ROOT_ADMIN_USERNAME, "root")
	viper.SetDefault(constants.ENV_ROOT_ADMIN_PASSWORD, "root")
	viper.SetDefault(constants.ENV_ROOT_ADMIN_EMAIL, "root@localhost")

	viper.SetDefault(constants.ENV_SQLITE_FILE, "auth_database.db")

	viper.AutomaticEnv()

	// use this to write down default config to a file
	// viper.WriteConfigAs("./config.yaml")

}
