package services

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
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

// CreateSession creates a new session for the user and returns the session id
// - Generates a new session id
// - Calls the storage layer to store the session information
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *authenticationService) CreateSession(user *entities.User) (*entities.Session, error) {

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
func (u *authenticationService) GetUserBySessionId(sessionId string) (*entities.User, error) {
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
func (u *authenticationService) LogoutUserBySessionId(sessionId string) error {

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

// GenerateJWT generates a signed JWT token
// - Generates a new JWT token
// - Signs the token with the private key
// ERRORS:
// - service: ErrJWTPrivateKey
func (u *authenticationService) GenerateJWT(claims *entities.CustomClaims) (string, error) {
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

// ValidateJWT validates the JWT token
// - Retrieves the public key
// - Validates the token
func (u *authenticationService) ValidateJWT(token string) (*entities.CustomClaims, error) {
	publicKey, err := helpers.GetJWTPublicKey()
	if err != nil {
		logger.Error("error getting public key: ", err)
		return nil, err
	}
	claims := &entities.CustomClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return claims, err
		}
		logger.Error("error verifying token: ", err)
		return claims, svrerr.ErrInvalidToken
	}
	return claims, nil
}
