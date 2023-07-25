/*
Copyright © 2023 Adharsh M adharshmk96@gmail.com
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "v0.1.2"
var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "stk-auth",
	Short: "Auth server is a simple authentication server",
	Long:  `Auth server is a simple authentication server that can be used to authenticate users.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "./stk.yaml", "config file.")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".stk" (without extension).
		viper.AddConfigPath("./")
		viper.SetConfigType("yaml")
		viper.SetConfigName("stk")
	}

	viper.AutomaticEnv()

	// Set the key replacer
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); errors.Is(err, nil) {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

}
