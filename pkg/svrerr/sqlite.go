package svrerr

import "errors"

var (
	// Account storage errors
	ErrStoringData    = errors.New("failed_storing_data")
	ErrRetrievingData = errors.New("failed_retrieving_data")
	ErrEntryNotFound  = errors.New("record_not_found")
	ErrDuplicateEntry = errors.New("duplicate_entry_on_unique_field")
)
