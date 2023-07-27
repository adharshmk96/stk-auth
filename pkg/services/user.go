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
func (u *authenticationService) CreateUser(user *entities.User) (*entities.User, error) {
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
func (u *authenticationService) Authenticate(login *entities.User) error {
	var userRecord *entities.User
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

func (u *authenticationService) GetUserByID(userId string) (*entities.User, error) {
	user, err := u.storage.GetUserByUserID(userId)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *authenticationService) ChangePassword(user *entities.User) error {
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

// GetUserList retrieves the list of users from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetUserList(limit int, offset int) ([]*entities.User, error) {

	if limit == 0 {
		limit = 10
	}

	users, err := u.storage.GetUserList(limit, offset)
	if err != nil {
		return nil, err
	}
	return users, nil
}

// GetTotalUsersCount retrieves the total number of users from the storage layer
// ERRORS:
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetTotalUsersCount() (int64, error) {
	totalUsers, err := u.storage.GetTotalUsersCount()
	if err != nil {
		return 0, err
	}
	return totalUsers, nil
}
