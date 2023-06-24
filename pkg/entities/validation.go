package entities

import "regexp"

const (
	EmailOrUsernameRequired = "Username or Email is required"
	PasswordRequired        = "Password is required"
	EmailMustBeValid        = "Email must be a valid format user@email.com"
	UsernameMustBeValid     = "Username must be at least 3 characters"
	PasswordMustBeValid     = "Password must be at least 8 characters"
)

func validateUsername(username string) error {
	if len(username) < 3 {
		return ErrInvalidUsername
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrInvalidPassword
	}
	return nil
}

func validateEmail(email string) error {
	// Validate email format
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

func ValidateUser(user *Account) map[string]string {
	errorMessages := make(map[string]string)

	if user.Username == "" && user.Email == "" {
		errorMessages["username"] = EmailOrUsernameRequired
		errorMessages["email"] = EmailOrUsernameRequired
	}

	if user.Password == "" {
		errorMessages["password"] = PasswordRequired
	}

	if user.Password != "" {
		if err := validatePassword(user.Password); err != nil {
			errorMessages["password"] = PasswordMustBeValid
		}
	}

	if user.Username != "" {
		if err := validateUsername(user.Username); err != nil {
			errorMessages["username"] = UsernameMustBeValid
		}
	}

	if user.Email != "" {
		if err := validateEmail(user.Email); err != nil {
			errorMessages["email"] = EmailMustBeValid
		}
	}

	return errorMessages
}
