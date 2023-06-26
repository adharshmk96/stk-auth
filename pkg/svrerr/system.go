package svrerr

import "errors"

var (
	ErrParsingUserID  = errors.New("invalid_user_id")
	ErrHasingPassword = errors.New("error_hashing_password")

	// Storage errors
	ErrStoringData    = errors.New("failed_storing_data")
	ErrRetrievingData = errors.New("failed_retrieving_data")
	ErrEntryNotFound  = errors.New("record_not_found")
	ErrDuplicateEntry = errors.New("duplicate_entry_on_unique_field")
)
