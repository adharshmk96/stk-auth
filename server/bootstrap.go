package server

import (
	"log"

	"github.com/adharshmk96/stk-auth/pkg/entities"
)

func CreateAdmin(service entities.UserManagementService) {
	// Initialize the service
	user := &entities.Account{
		Username: "admin",
		Password: "admin",
		Email:    "user@admin.com",
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
