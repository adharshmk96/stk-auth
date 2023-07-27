/*
Copyright © 2023 Adharsh M adharshmk96@gmail.com
*/
package cmd

import (
	"fmt"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/storage/user/sqlite"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// creates user via add user --username <username> --email <email> --password <password>
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Creates a new user in the auth server",
	Run: func(cmd *cobra.Command, args []string) {
		userName := cmd.Flag("username").Value.String()
		email := cmd.Flag("email").Value.String()
		password := cmd.Flag("password").Value.String()

		conn := db.GetSqliteConnection(viper.GetString(constants.ENV_SQLITE_FILE))
		userStorage := sqlite.NewAccountStorage(conn)
		userService := services.NewUserManagementService(userStorage)

		user := &entities.User{
			Username: userName,
			Email:    email,
			Password: password,
		}

		createdUser, err := userService.CreateUser(user)
		if err != nil {
			fmt.Println("Error creating user", err)
			return
		}

		fmt.Println(createdUser)

		fmt.Println("User created successfully")

	},
}

// addCmd represents the version command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "display the version of the auth server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("auth server version: %s\n", version)
	},
}

func init() {

	userCmd.Flags().StringP("username", "u", "", "username of the user")
	userCmd.Flags().StringP("email", "e", "", "email of the user")
	userCmd.Flags().StringP("password", "p", "", "password of the user")

	addCmd.AddCommand(userCmd)

	rootCmd.AddCommand(addCmd)

}
