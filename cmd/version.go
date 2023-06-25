/*
Copyright © 2023 Adharsh M adharshmk96@gmail.com
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "display the version of the auth server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("auth server version: %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
