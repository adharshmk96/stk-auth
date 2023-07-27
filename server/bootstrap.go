package server

import (
	"log"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/spf13/viper"
)

func CreateAdmin(service entities.AuthenticationService) {
	adminUsername := viper.GetString(constants.ENV_ROOT_ADMIN_USERNAME)
	adminPassword := viper.GetString(constants.ENV_ROOT_ADMIN_PASSWORD)
	adminEmail := viper.GetString(constants.ENV_ROOT_ADMIN_EMAIL)
	// Initialize the service
	user := &entities.User{
		Username: adminUsername,
		Password: adminPassword,
		Email:    adminEmail,
	}

	// Create the admin user
	account, err := service.CreateUser(user)
	if err != nil {
		log.Println("Error creating admin user: ", err)
	}

	if account == nil {
		log.Println("Admin user not created")
		return
	}

	err = service.AddUserToGroup(account.ID, "admin")
	if err != nil {
		log.Println("Error adding admin user to admin group: ", err)
	}

	log.Println("Admin user created: ", account.Username)

}
