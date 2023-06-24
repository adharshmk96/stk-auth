package svrerr

import "errors"

var (
	// Account storage errors
	ErrStoringAccount    = errors.New("failed_storing_user_data")
	ErrRetrievingAccount = errors.New("failed_retrieving_user_data")
	ErrAccountNotFound   = errors.New("user_not_found")
	ErrAccountExists     = errors.New("user_already_exists")
)
