package svrerr

import "errors"

var (
	ErrHasingPassword     = errors.New("error_hashing_password")
	ErrInvalidCredentials = errors.New("error_invalid_credentials")
)
