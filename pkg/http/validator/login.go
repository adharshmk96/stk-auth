package validator

import (
	"github.com/adharshmk96/auth-server/pkg/entities"
)

func ValidateLogin(login *entities.Account) map[string]string {
	errorMessages := make(map[string]string)

	if login.Username == "" && login.Email == "" {
		errorMessages["username"] = "username or email is required"
		errorMessages["email"] = "username or email is required"
	}

	if login.Username != "" && login.Email != "" {
		errorMessages["username"] = "username cannot be used with email"
		errorMessages["email"] = "email cannot be used with  username"
	}

	if login.Password == "" {
		errorMessages["password"] = "password is required"
	}

	return errorMessages
}
