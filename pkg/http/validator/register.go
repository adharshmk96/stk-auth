package validator

import (
	"regexp"
	"unicode"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
)

const (
	EmailIsRequired     = "Email is required"
	PasswordRequired    = "Password is required"
	EmailMustBeValid    = "Email must be a valid format user@email.com"
	UsernameMustBeValid = "Username must be at least 3 characters"
	PasswordMustBeValid = "Password must have at least 8 characters, 1 uppercase, 1 lowercase, 1 number, and 1 special character"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func registrationUsername(username string) error {
	if len(username) < 3 {
		return ErrInvalidUsername
	}
	return nil
}

func registrationPassword(password string) error {
	var (
		hasMinLen    = false
		hasUppercase = false
		hasLowercase = false
		hasNumber    = false
		hasSpecial   = false
	)

	hasMinLen = len(password) >= 8

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUppercase = true
		case unicode.IsLower(char):
			hasLowercase = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if hasMinLen && hasUppercase && hasLowercase && hasNumber && hasSpecial {
		return nil
	} else {
		return ErrInvalidPassword
	}
}

func registrationEmail(email string) error {
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

func ValidateRegistration(user *ds.Account) map[string]string {
	errorMessages := make(map[string]string)

	if user.Email == "" {
		errorMessages["email"] = EmailIsRequired
	} else {
		if user.Username != "" {
			if err := registrationUsername(user.Username); err != nil {
				errorMessages["username"] = UsernameMustBeValid
			}
		}

		if user.Email != "" {
			if err := registrationEmail(user.Email); err != nil {
				errorMessages["email"] = EmailMustBeValid
			}
		}
	}

	if user.Password == "" {
		errorMessages["password"] = PasswordRequired
	} else {
		if err := registrationPassword(user.Password); err != nil {
			errorMessages["password"] = PasswordMustBeValid
		}
	}

	return errorMessages
}
