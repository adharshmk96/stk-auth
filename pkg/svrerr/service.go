package svrerr

import "errors"

var (
	// Account service errors
	ErrHasingPassword = errors.New("error_hashing_password")
)
