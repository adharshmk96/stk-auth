package infra

import "github.com/spf13/viper"

// Configurations are loaded from the environment variables using viper.
// callin this function will reLoad the config. (useful for testing)
// WARN: this will reload all the config.
func LoadDefaultConfig() {
	viper.SetDefault(ENV_SQLITE_FILEPATH, "database.db")

	viper.AutomaticEnv()
}
