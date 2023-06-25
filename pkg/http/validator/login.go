package validator

import (
	"github.com/adharshmk96/auth-server/pkg/entities"
)

const (
	UsernameOrEmailRequired = "username or email is required"
	UsernameEmailUsed       = "username cannot be used with email"
	EmailUserNameUsed       = "email cannot be used with username"
)

func ValidateLogin(login *entities.Account) map[string]string {
	errorMessages := make(map[string]string)

	if login.Username == "" && login.Email == "" {
		errorMessages["username"] = UsernameOrEmailRequired
		errorMessages["email"] = UsernameOrEmailRequired
	}

	if login.Username != "" && login.Email != "" {
		errorMessages["username"] = UsernameEmailUsed
		errorMessages["email"] = EmailUserNameUsed
	}

	if login.Password == "" {
		errorMessages["password"] = PasswordRequired
	}

	return errorMessages
}