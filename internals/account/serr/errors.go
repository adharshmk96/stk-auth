package serr

import "errors"

var (
	ErrAccountFailed = errors.New("account failed")
)

// Service error
var (
	ErrHasingPassword = errors.New("error hashing password")
	ErrPasswordEmpty  = errors.New("password cannot be empty")
	ErrAccountExists  = errors.New("account already exists")

	// Session
	ErrStartingSession = errors.New("error starting session")
	ErrGettingSession  = errors.New("error getting session")
	ErrEndingSession   = errors.New("error ending session")
)

// Storage error
var (
	ErrInsertAccountFailed = errors.New("insert account failed")
	ErrUniqueConstraint    = errors.New("unique constraint failed")
	ErrGetAccountFailed    = errors.New("get account failed")
)
