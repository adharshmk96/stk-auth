package svrerr

import "errors"

var (
	// Account storage errors
	ErrStoringAccount    = errors.New("failed_storing_user_data")
	ErrRetrievingAccount = errors.New("failed_retrieving_user_data")
	ErrNoAccountFound    = errors.New("user_not_found")
)
