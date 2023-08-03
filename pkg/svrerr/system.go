package svrerr

import "errors"

var (
	ErrParsingAccountID = errors.New("invalid_account_id")
	ErrHasingPassword   = errors.New("error_hashing_password")

	// Storage errors
	ErrDBStorageFailed  = errors.New("storage_error")
	ErrDBEntryNotFound  = errors.New("record_not_found")
	ErrDBDuplicateEntry = errors.New("duplicate_entry_on_unique_field")
)
