package services

import (
	"time"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
	"github.com/google/uuid"
)

func (u *accountService) RegisterUser(user *entities.Account) (*entities.Account, error) {
	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return nil, svrerr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(user.Password, salt)

	current_timestamp := time.Now()
	newUserId := uuid.New()

	user.ID = entities.UserID(newUserId)
	user.CreatedAt = current_timestamp
	user.UpdatedAt = current_timestamp
	user.Password = hashedPassword
	user.Salt = hashedSalt

	if err = u.storage.SaveUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (u *accountService) LoginSessionUser(user *entities.Account) (*entities.Account, error) {
	userRecord, err := u.storage.GetUserByEmail(user.Email)
	if err != nil {
		if err == svrerr.ErrAccountNotFound {
			return nil, svrerr.ErrInvalidCredentials
		}
		return nil, err
	}

	valid, err := utils.VerifyPassword(userRecord.Password, userRecord.Salt, user.Password)
	if err != nil {
		logger.Error("error verifying password: ", err)
		return nil, err
	}
	if !valid {
		return nil, svrerr.ErrInvalidCredentials
	}

	return userRecord, nil
}
