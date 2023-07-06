package services

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/google/uuid"
)

// CreateSession creates a new session for the user and returns the session id
// - Generates a new session id
// - Calls the storage layer to store the session information
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *userManagementService) CreateSession(user *entities.Account) (*entities.Session, error) {

	userId := user.ID
	newSessionId := uuid.New().String()
	currentTimestamp := time.Now()

	if userId == entities.UserID(uuid.Nil) {
		return nil, svrerr.ErrInvalidSession
	}

	session := &entities.Session{
		UserID:    userId,
		SessionID: newSessionId,
		CreatedAt: currentTimestamp,
		UpdatedAt: currentTimestamp,
		Valid:     true,
	}

	if err := u.storage.SaveSession(session); err != nil {
		return nil, err
	}

	return session, nil
}

// GetUserBySessionId retrieves and returns the user information by sesion id
// - Calls the storage layer to retrieve the session information
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed
func (u *userManagementService) GetUserBySessionId(sessionId string) (*entities.Account, error) {
	user, err := u.storage.GetUserBySessionID(sessionId)
	if err != nil {
		if errors.Is(err, svrerr.ErrDBEntryNotFound) {
			return nil, svrerr.ErrInvalidSession
		}
		return nil, err
	}

	return user, nil
}

// LogoutUserBySessionId invalidates the session id
// - Calls the storage layer to set the session validity
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *userManagementService) LogoutUserBySessionId(sessionId string) error {

	err := u.storage.InvalidateSessionByID(sessionId)
	if err != nil {
		if errors.Is(err, svrerr.ErrDBStorageFailed) || errors.Is(err, svrerr.ErrDBEntryNotFound) {
			return svrerr.ErrInvalidSession
		} else {
			return err
		}
	}

	return nil
}

// Session.
// NOTE:
// - For a session based authentication, the invalidated session ID can't be used anymore.
// - For a token based authentication, even if the session is invalidated, the token can be re-used until it expires, the token won't be refreshed anymore.
