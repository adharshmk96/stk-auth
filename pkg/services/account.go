package services

import (
	"time"

	"github.com/adharshmk96/auth-server/pkg/entities"
	"github.com/adharshmk96/auth-server/pkg/infra/config"
	"github.com/adharshmk96/auth-server/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt"
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

func (u *accountService) LoginUserSessionToken(user *entities.Account) (string, error) {
	var userRecord *entities.Account
	var err error
	if user.Email == "" {
		userRecord, err = u.storage.GetUserByUsername(user.Username)
	} else {
		userRecord, err = u.storage.GetUserByEmail(user.Email)
	}
	if err != nil {
		if err == svrerr.ErrEntryNotFound {
			return "", svrerr.ErrInvalidCredentials
		}
		return "", err
	}

	valid, err := utils.VerifyPassword(userRecord.Password, userRecord.Salt, user.Password)
	if err != nil {
		logger.Error("error verifying password: ", err)
		return "", err
	}
	if !valid {
		return "", svrerr.ErrInvalidCredentials
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
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, getClaims(session.SessionID, userRecord.ID.String()))
	private_key, err := config.GetJWTPrivateKey()
	if err != nil {
		logger.Error("error getting private key: ", err)
		return "", err
	}

	signedToken, err := token.SignedString(private_key)
	if err != nil {
		logger.Error("error signing token: ", err)
		return "", err
	}

	return signedToken, nil
}
