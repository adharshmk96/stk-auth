package services

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/google/uuid"
)

// CreateUser stores user details and returns the stored user details
// - Hashes the password, Assigns a user id, Generates a salt
// - Calls the storage layer to store the user information
// ERRORS:
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
func (u *accountService) CreateUser(user *entities.Account) (*entities.Account, error) {
	if user.Email == "" {
		return nil, svrerr.ErrValidationFailed
	}

	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return nil, svrerr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(user.Password, salt)

	newUserId := uuid.New()
	currentTimestamp := time.Now()

	user.ID = entities.UserID(newUserId)
	user.CreatedAt = currentTimestamp
	user.UpdatedAt = currentTimestamp
	user.Password = hashedPassword
	user.Salt = hashedSalt

	if err = u.storage.SaveUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// Authenticate validates the user login information
// - Retrieves the user from the storage layer
// - Verifies the password
// - fills the user info retrieved from storage layer
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBEntryNotFound, ErrDBStorageFailed
func (u *accountService) Authenticate(login *entities.Account) error {
	var userRecord *entities.Account
	var err error
	if login.Email == "" {
		userRecord, err = u.storage.GetUserByUsername(login.Username)
	} else {
		userRecord, err = u.storage.GetUserByEmail(login.Email)
	}
	if err != nil {
		if errors.Is(err, svrerr.ErrDBEntryNotFound) {
			return svrerr.ErrInvalidCredentials
		}
		return err
	}

	valid, err := utils.VerifyPassword(userRecord.Password, userRecord.Salt, login.Password)
	if err != nil {
		logger.Error("error verifying password: ", err)
		return err
	}
	if !valid {
		return svrerr.ErrInvalidCredentials
	}
	login.ID = userRecord.ID
	login.Username = userRecord.Username
	login.Email = userRecord.Email
	login.CreatedAt = userRecord.CreatedAt
	login.UpdatedAt = userRecord.UpdatedAt
	return nil
}

func (u *accountService) GetUserByID(userId string) (*entities.Account, error) {
	user, err := u.storage.GetUserByUserID(userId)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *accountService) ChangePassword(user *entities.Account) error {
	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return svrerr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(user.Password, salt)

	currentTimestamp := time.Now()

	user.UpdatedAt = currentTimestamp
	user.Password = hashedPassword
	user.Salt = hashedSalt

	if err = u.storage.UpdateUserByID(user); err != nil {
		return err
	}

	return nil
}
