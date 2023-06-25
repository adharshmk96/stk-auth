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

func (u *accountService) LoginSessionUser(user *entities.Account) (*entities.Session, error) {
	userRecord, err := u.storage.GetUserByEmail(user.Email)
	if err != nil {
		if err == svrerr.ErrEntryNotFound {
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

	newSessionId := uuid.New().String()
	currentTimestamp := time.Now()

	session := &entities.Session{
		UserID:    userRecord.ID,
		SessionID: newSessionId,
		CreatedAt: currentTimestamp,
		UpdatedAt: currentTimestamp,
		Valid:     true,
	}

	if err = u.storage.SaveSession(session); err != nil {
		return nil, err
	}

	return session, nil
}
