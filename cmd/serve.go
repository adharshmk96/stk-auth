/*
Copyright © 2023 Adharsh M adharshmk96@gmail.com
*/
package cmd

import (
	"sync"

	"github.com/adharshmk96/stk-auth/server"
	"github.com/spf13/cobra"
)

var startingPort string

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the auth server",
	Run: func(cmd *cobra.Command, args []string) {
		var wg sync.WaitGroup

		wg.Add(1)

		startAddr := "0.0.0.0:"

		go func() {
			defer wg.Done()
			_, done := server.StartHttpServer(startAddr + startingPort)
			// blocks the routine until done is closed
			<-done
		}()

		wg.Wait()
	},
}

func init() {
	serveCmd.Flags().StringVarP(&startingPort, "port", "p", "8080", "Port to start the server on")

	rootCmd.AddCommand(serveCmd)
}
