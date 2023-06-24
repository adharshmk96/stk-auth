package entities

import "errors"

var (
	ErrParsingUserID = errors.New("invalid_user_id")

	ErrInvalidUsername = errors.New("invalid_username")
	ErrInvalidPassword = errors.New("invalid_password")
	ErrInvalidEmail    = errors.New("invalid_email")
)
