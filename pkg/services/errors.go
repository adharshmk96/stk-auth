package services

import "errors"

var (
	ErrStoringAccount = errors.New("error_storing_user_data")
	ErrHasingPassword = errors.New("error_hashing_password")
)
