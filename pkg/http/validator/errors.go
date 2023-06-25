package validator

import "errors"

var (
	ErrInvalidUsername = errors.New("invalid_username")
	ErrInvalidPassword = errors.New("invalid_password")
	ErrInvalidEmail    = errors.New("invalid_email")
)
