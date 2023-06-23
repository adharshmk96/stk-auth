/*
Copyright © 2023 Adharsh M adharshmk96@gmail.com
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var port string

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the auth server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("serve called")
	},
}

func init() {
	serveCmd.Flags().StringVarP(&port, "port", "p", "8080", "Port to listen on")
	rootCmd.AddCommand(serveCmd)
}
