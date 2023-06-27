package svrerr

import "errors"

var (
	ErrParsingUserID  = errors.New("invalid_user_id")
	ErrHasingPassword = errors.New("error_hashing_password")

	// Storage errors
	ErrDBUpdatingData   = errors.New("failed_updating_data")
	ErrDBStoringData    = errors.New("failed_storing_data")
	ErrDBRetrievingData = errors.New("failed_retrieving_data")
	ErrDBEntryNotFound  = errors.New("record_not_found")
	ErrDBDuplicateEntry = errors.New("duplicate_entry_on_unique_field")
)
