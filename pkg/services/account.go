package services

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra/config"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/utils"
	"github.com/golang-jwt/jwt/v5"
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

func (u *accountService) LoginUserSession(user *entities.Account) (*entities.Session, error) {
	var userRecord *entities.Account
	var err error
	if user.Email == "" {
		userRecord, err = u.storage.GetUserByUsername(user.Username)
	} else {
		userRecord, err = u.storage.GetUserByEmail(user.Email)
	}
	if err != nil {
		if err == svrerr.ErrDBEntryNotFound {
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

func (u *accountService) LoginUserSessionToken(user *entities.Account) (string, error) {
	var userRecord *entities.Account
	var err error
	if user.Email == "" {
		userRecord, err = u.storage.GetUserByUsername(user.Username)
	} else {
		userRecord, err = u.storage.GetUserByEmail(user.Email)
	}
	if err != nil {
		if err == svrerr.ErrDBEntryNotFound {
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

	claims := NewCustomClaims(userRecord.ID.String(), session.SessionID)
	private_key, err := config.GetJWTPrivateKey()
	if err != nil {
		logger.Error("error getting private key: ", err)
		return "", err
	}
	signedToken, err := GetSignedToken(private_key, claims)
	if err != nil {
		logger.Error("error generating token: ", err)
		return "", err
	}

	return signedToken, nil
}

func (u *accountService) GetUserBySessionId(sessionId string) (*entities.Account, error) {
	user, err := u.storage.GetUserBySessionID(sessionId)
	if err != nil {
		if err == svrerr.ErrDBEntryNotFound {
			return nil, svrerr.ErrInvalidSession
		}
		return nil, err
	}

	return user, nil
}

// TODO: refactor this
func (u *accountService) GetUserBySessionToken(sessionToken string) (*entities.AccountWithToken, error) {

	publicKey, err := config.GetJWTPublicKey()
	if err != nil {
		logger.Error("error getting public key: ", err)
		return nil, err
	}

	claims, err := verifyToken(publicKey, sessionToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			user, err := u.storage.GetUserBySessionID(claims.SessionID)
			if err != nil {
				if err == svrerr.ErrDBEntryNotFound {
					return nil, svrerr.ErrInvalidSession
				}
				return nil, err
			}

			logger.Info("token expired, session is valid, refreshing token")

			claims := NewCustomClaims(claims.UserID, claims.SessionID)
			private_key, err := config.GetJWTPrivateKey()
			if err != nil {
				logger.Error("error getting private key: ", err)
				return nil, err
			}
			signedToken, err := GetSignedToken(private_key, claims)
			if err != nil {
				logger.Error("error generating token: ", err)
				return nil, err
			}

			accountWithToken := &entities.AccountWithToken{
				Account: *user,
				Token:   signedToken,
			}
			return accountWithToken, nil
		}
		return nil, svrerr.ErrInvalidToken
	}

	userId := claims.UserID
	user, err := u.storage.GetUserByUserID(userId)
	if err != nil {
		if err == svrerr.ErrDBEntryNotFound {
			return nil, svrerr.ErrInvalidSession
		}
		return nil, err
	}

	accountWithToken := &entities.AccountWithToken{
		Account: *user,
		Token:   sessionToken,
	}
	return accountWithToken, nil

}
