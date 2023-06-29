/*
Copyright © 2023 Adharsh M adharshmk96@gmail.com
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "v0.1.1"

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

func initialSetup() {
	viper.AutomaticEnv()
}

func init() {
	cobra.OnInitialize(initialSetup)
}
