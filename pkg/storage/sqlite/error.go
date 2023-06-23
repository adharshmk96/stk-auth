package sqlite

import "errors"

var (
	ErrStoringAccount    = errors.New("error_storing_user_data")
	ErrRetrievingAccount = errors.New("error_retrieving_user_data")
	ErrNoAccountFound    = errors.New("no_user_found")
)
