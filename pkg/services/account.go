package services

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// RegisterUser stores user details and returns the stored user details
// - Hashes the password, Assigns a user id, Generates a salt
// - Calls the storage layer to store the user information
// ERRORS:
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
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

// ValidateLogin validates the user login information
// - Retrieves the user from the storage layer
// - Verifies the password
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBEntryNotFound, ErrDBStorageFailed
func (u *accountService) ValidateLogin(login *entities.Account) error {
	var userRecord *entities.Account
	var err error
	if login.Email == "" {
		userRecord, err = u.storage.GetUserByUsername(login.Username)
	} else {
		userRecord, err = u.storage.GetUserByEmail(login.Email)
	}
	if err != nil {
		if err == svrerr.ErrDBEntryNotFound {
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
	return nil
}

// LoginUserSession creates a new session for the user and returns the session id
// - Retrieves the user from the storage layer
// - Verifies the password
// - Generates a new session id
// - Calls the storage layer to store the session information
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *accountService) LoginUserSession(user *entities.Account) (*entities.Session, error) {
	// TODO: Move this to handler and change this to generate session
	err := u.ValidateLogin(user)
	if err != nil {
		return nil, err
	}

	userId := user.ID
	newSessionId := uuid.New().String()
	currentTimestamp := time.Now()

	session := &entities.Session{
		UserID:    userId,
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

// GenerateJWT generates a signed JWT token
// - Generates a new JWT token
// - Signs the token with the private key
// ERRORS:
// - service: ErrJWTPrivateKey
func (u *accountService) GenerateJWT(user *entities.Account, session *entities.Session) (string, error) {
	userId := user.ID.String()
	sessionId := session.SessionID

	timeNow := time.Now()

	claims := customClaims{
		SessionID: sessionId,
		UserID:    userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			Issuer:    viper.GetString(constants.ENV_JWT_SUBJECT),
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_JWT_EXPIRATION_DURATION))),
		},
	}

	privateKey, err := helpers.GetJWTPrivateKey()
	if err != nil {
		logger.Error("error getting private key: ", err)
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		logger.Error("error signing token: ", err)
		return "", err
	}
	return signedToken, err
}

// GetUserBySessionId retrieves and returns the user information by sesion id
// - Calls the storage layer to retrieve the session information
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
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

// GetUserBySessionToken retrieves and returns the user information by sesion token
// - Validates the token, and retrieves the session_id claim
// - Calls the storage layer to retrieve the session information
// - Refreshes the token if it is expired
// - Returns the user information with valid token
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *accountService) GetUserBySessionToken(sessionToken string) (*entities.AccountWithToken, error) {
	// TODO: refactor this

	claims, err := helpers.VerifyToken(sessionToken)
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

			claims := helpers.MakeCustomClaims(claims.UserID, claims.SessionID)
			signedToken, err := helpers.GetSignedTokenWithClaims(claims)
			if err != nil {
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

// LogoutUserBySessionId invalidates the session id
// - Calls the storage layer to set the session validity
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *accountService) LogoutUserBySessionId(sessionId string) error {

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

// LogoutUserBySessionToken invalidates the session token
// - Validates the token, and retrieves the session_id claim
// - Calls the storage layer to set the session validity
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *accountService) LogoutUserBySessionToken(sessionToken string) error {

	claims, err := helpers.VerifyToken(sessionToken)
	if err != nil {
		if !errors.Is(err, jwt.ErrTokenExpired) {
			return svrerr.ErrInvalidToken
		}
	}

	sessionId := claims.SessionID

	err = u.storage.InvalidateSessionByID(sessionId)
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
