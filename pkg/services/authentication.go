package services

import (
	"errors"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/services/helpers"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// CreateAccount stores account details and returns the stored account details
// - Hashes the password, Assigns a account id, Generates a salt
// - Calls the storage layer to store the account information
// ERRORS:
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
func (u *authenticationService) CreateAccount(account *ds.Account) (*ds.Account, error) {
	if account.Email == "" {
		return nil, svrerr.ErrValidationFailed
	}

	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return nil, svrerr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(account.Password, salt)

	newAccountId := uuid.New()
	currentTimestamp := time.Now()

	account.ID = ds.AccountID(newAccountId)
	account.CreatedAt = currentTimestamp
	account.UpdatedAt = currentTimestamp
	account.Password = hashedPassword
	account.Salt = hashedSalt

	if err = u.storage.SaveAccount(account); err != nil {
		return nil, err
	}

	return account, nil
}

// Authenticate validates the account login information
// - Retrieves the account from the storage layer
// - Verifies the password
// - fills the account info retrieved from storage layer
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBEntryNotFound, ErrDBStorageFailed
func (u *authenticationService) Authenticate(login *ds.Account) error {
	var accountRecord *ds.Account
	var err error
	if login.Email == "" {
		accountRecord, err = u.storage.GetAccountByUsername(login.Username)
	} else {
		accountRecord, err = u.storage.GetAccountByEmail(login.Email)
	}
	if err != nil {
		if errors.Is(err, svrerr.ErrDBEntryNotFound) {
			return svrerr.ErrInvalidCredentials
		}
		return err
	}

	valid, err := utils.VerifyPassword(accountRecord.Password, accountRecord.Salt, login.Password)
	if err != nil {
		logger.Error("error verifying password: ", err)
		return err
	}
	if !valid {
		return svrerr.ErrInvalidCredentials
	}
	login.ID = accountRecord.ID
	login.Username = accountRecord.Username
	login.Email = accountRecord.Email
	login.CreatedAt = accountRecord.CreatedAt
	login.UpdatedAt = accountRecord.UpdatedAt
	return nil
}

func (u *authenticationService) GetAccountByID(accountId string) (*ds.Account, error) {
	account, err := u.storage.GetAccountByAccountID(accountId)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (u *authenticationService) ChangePassword(account *ds.Account) error {
	salt, err := utils.GenerateSalt()
	if err != nil {
		logger.Error("error generating salt: ", err)
		return svrerr.ErrHasingPassword
	}

	hashedPassword, hashedSalt := utils.HashPassword(account.Password, salt)

	currentTimestamp := time.Now()

	account.UpdatedAt = currentTimestamp
	account.Password = hashedPassword
	account.Salt = hashedSalt

	if err = u.storage.UpdateAccountByID(account); err != nil {
		return err
	}

	return nil
}

// CreateSession creates a new session for the account and returns the session id
// - Generates a new session id
// - Calls the storage layer to store the session information
// ERRORS:
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *authenticationService) CreateSession(account *ds.Account) (*ds.Session, error) {

	accountId := account.ID
	newSessionId := uuid.New().String()
	currentTimestamp := time.Now()

	if accountId == ds.AccountID(uuid.Nil) {
		return nil, svrerr.ErrInvalidSession
	}

	session := &ds.Session{
		AccountID: accountId,
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

// GetAccountBySessionId retrieves and returns the account information by sesion id
// - Calls the storage layer to retrieve the session information
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed
func (u *authenticationService) GetAccountBySessionId(sessionId string) (*ds.Account, error) {
	account, err := u.storage.GetAccountBySessionID(sessionId)
	if err != nil {
		if errors.Is(err, svrerr.ErrDBEntryNotFound) {
			return nil, svrerr.ErrInvalidSession
		}
		return nil, err
	}

	return account, nil
}

// LogoutAccountBySessionId invalidates the session id
// - Calls the storage layer to set the session validity
// ERRORS:
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed, ErrDBEntryNotFound
func (u *authenticationService) LogoutAccountBySessionId(sessionId string) error {

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

// SendPasswordResetEmail sends a password reset email to the user
// - Generates a password reset token
// - Sends the password reset email
func (u *authenticationService) SendPasswordResetEmail(email string) error {
	account, err := u.storage.GetAccountByEmail(email)
	if err != nil {
		return err
	}

	resetToken := uuid.New().String()
	resetTokenExpiry := time.Now().Add(time.Minute * 30)

	if err = u.storage.SavePasswordResetToken(account.ID.String(), resetToken, resetTokenExpiry); err != nil {
		return err
	}

	if err = helpers.SendPasswordResetEmail(email, resetToken); err != nil {
		return err
	}

	return nil
}

// ResetPassword resets the password for the account
// - Validates the reset token
// - Resets the password
func (u *authenticationService) ResetPassword(token string, password string) error {
	account, err := u.storage.GetAccountByPasswordResetToken(token)
	if err != nil {
		if errors.Is(err, svrerr.ErrDBEntryNotFound) {
			return svrerr.ErrInvalidToken
		}
		return err
	}

	account.Password = password

	err = u.ChangePassword(account)
	if err != nil {
		return err
	}

	err = u.storage.InvalidateResetToken(token)
	if err != nil {
		return err
	}

	return nil
}
