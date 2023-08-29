package server

import (
	"log"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/spf13/viper"
)

func CreateAdmin(service entities.AuthenticationService) {
	adminUsername := viper.GetString(constants.ENV_ROOT_ADMIN_USERNAME)
	adminPassword := viper.GetString(constants.ENV_ROOT_ADMIN_PASSWORD)
	adminEmail := viper.GetString(constants.ENV_ROOT_ADMIN_EMAIL)
	// Initialize the service
	account := &ds.Account{
		Username: adminUsername,
		Password: adminPassword,
		Email:    adminEmail,
	}

	// Create the admin account
	account, err := service.CreateAccount(account)
	if err != nil {
		log.Println("Error creating admin account: ", err)
	}

	if account == nil {
		log.Println("Admin account not created")
		return
	}

	err = service.AddAccountToGroup(account.ID, "admin")
	if err != nil {
		log.Println("Error adding admin account to admin group: ", err)
	}

	log.Println("Admin account created: ", account.Username)

}
