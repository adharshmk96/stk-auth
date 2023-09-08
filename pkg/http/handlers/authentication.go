package handlers

import (
	"errors"
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

var (
	secureCookie, sameSite = transport.GetCookieModes()
)

// RegisterAccount registers a new account
// - Decodes and Validates the account information from body
// - Calls the service layer to store the account information
// - Returns the account information
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
func (h *accountHandler) RegisterAccount(gc *gsk.Context) {
	var account *ds.Account

	err := gc.DecodeJSONBody(&account)
	if err != nil {
		transport.HandleJsonDecodeError(err, gc)
		return
	}

	errorMessages := validator.ValidateRegistration(account)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, gc)
		return
	}

	createdAccount, err := h.authService.CreateAccount(account)
	if err != nil {
		transport.HandleRegistrationError(err, gc)
		return
	}

	response := transport.AccountResponse{
		ID:        createdAccount.ID.String(),
		Username:  createdAccount.Username,
		Email:     createdAccount.Email,
		CreatedAt: createdAccount.CreatedAt,
		UpdatedAt: createdAccount.UpdatedAt,
	}

	gc.Status(http.StatusCreated).JSONResponse(response)
}

// ChangeCredentials changes the password of the account
// - Decodes and Validates the account information from body
// - Calls the service layer to change the password
// - Returns the success message
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword, ErrInvalidCredentials, ErrDBEntryNotFound
// - storage: ErrDBStorageFailed
func (h *accountHandler) ChangeCredentials(gc *gsk.Context) {
	var credentials *transport.CredentialUpdateRequest

	err := gc.DecodeJSONBody(&credentials)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	creds := credentials.Credentials

	err = h.authService.Authenticate(creds)
	if err != nil {
		transport.HandleChangePasswordError(err, gc)
		return
	}

	newCreds := credentials.NewCredentials

	err = h.authService.ChangePassword(newCreds)
	if err != nil {
		transport.HandleChangePasswordError(err, gc)
		return
	}

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_CHANGED_PASSWORD,
	})
}

// LoginAccountSession creates a new session for the account and sets the session id in cookie
// - Decodes and Validates the account information from body
// - Calls the service layer to authenticate and store the session information
// - Sets the session id in cookie
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed
// NOTE:
// - session id should not be exposed to client, it should be in httpOnly cookie
func (h *accountHandler) LoginAccountSession(gc *gsk.Context) {
	var accountLogin *ds.Account

	err := gc.DecodeJSONBody(&accountLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, gc)
		return
	}

	errorMessages := validator.ValidateLogin(accountLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, gc)
		return
	}

	err = h.authService.Authenticate(accountLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	sessionData, err := h.authService.CreateSession(accountLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	accountData, err := h.authService.GetAccountByID(sessionData.AccountID.String())
	if err != nil {
		transport.HandleGetAccountError(err, gc)
		return
	}

	cookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
		Value:    sessionData.SessionID,
		HttpOnly: true,
		Path:     "/",
		SameSite: sameSite,
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
		Secure:   secureCookie,
	}

	response := transport.AccountResponse{
		ID:        accountData.ID.String(),
		Username:  accountData.Username,
		Email:     accountData.Email,
		CreatedAt: accountData.CreatedAt,
		UpdatedAt: accountData.UpdatedAt,
	}

	gc.SetCookie(cookie)
	gc.Status(http.StatusOK).JSONResponse(response)
}

// GetSessionAccount returns the account information from session id
// - Gets the session id from cookie
// - Calls the service layer to get the account information
// - Returns the account information
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed
func (h *accountHandler) GetSessionAccount(gc *gsk.Context) {
	sessionCookie, err := gc.GetCookie(viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
	if err != nil || sessionCookie == nil || sessionCookie.Value == "" {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	account, err := h.authService.GetAccountBySessionId(sessionCookie.Value)
	if err != nil {
		if errors.Is(err, svrerr.ErrInvalidSession) {
			gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
		} else {
			gc.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
				"message": transport.INTERNAL_SERVER_ERROR,
			})
		}
		return
	}

	response := transport.AccountResponse{
		ID:        account.ID.String(),
		Username:  account.Username,
		Email:     account.Email,
		CreatedAt: account.CreatedAt,
		UpdatedAt: account.UpdatedAt,
	}

	gc.Status(http.StatusOK).JSONResponse(response)
}

// LogoutAccount logs out the account
// - Gets the session id or session toekn from cookie
// - Calls the service layer to invalidate the session
// - Returns the success message
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidSession, ErrInvalidToken
// - storage: ErrDBStorageFailed
func (h *accountHandler) LogoutAccount(gc *gsk.Context) {
	sessionCookie, refreshToken, err := transport.GetSessionOrTokenFromCookie(gc)
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	if sessionCookie != nil && sessionCookie.Value != "" {
		err := h.authService.LogoutAccountBySessionId(sessionCookie.Value)
		if err != nil {
			transport.HandleLogoutError(err, gc)
			return
		}
	} else {
		_, err := h.authService.ValidateJWT(refreshToken.Value)
		if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
			transport.HandleLogoutError(err, gc)
			return
		}

	}

	sessionCookieName := viper.GetString(constants.ENV_SESSION_COOKIE_NAME)
	atCookieName := viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME)
	rtCookieName := viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME)

	newSessionCookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
		// Expires:  time.Unix(0, 0),
		MaxAge: -1,
	}

	atCookie := &http.Cookie{
		Name:     atCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
		// Expires:  time.Unix(0, 0),
		MaxAge: -1,
	}

	rtCookie := &http.Cookie{
		Name:     rtCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
		// Expires:  time.Unix(0, 0),
		MaxAge: -1,
	}

	gc.SetCookie(newSessionCookie)
	gc.SetCookie(atCookie)
	gc.SetCookie(rtCookie)

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_LOGOUT,
	})
}

// ResetPassword resets the password of the account
// - Decodes and Validates the account information from body
// - Calls the service layer to reset the password
// - Returns the success message
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword, ErrInvalidCredentials, ErrDBEntryNotFound
// - storage: ErrDBStorageFailed
func (h *accountHandler) ResetPassword(gc *gsk.Context) {
	var account *ds.Account

	err := gc.DecodeJSONBody(&account)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	email := account.Email

	err = h.authService.SendPasswordResetEmail(email)
	if err != nil {
		gc.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"message": transport.INTERNAL_SERVER_ERROR,
		})
		return
	}

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_RESET_PASSWORD_LINK,
	})
}

// ResetPasswordConfirm resets the password of the account
// - Decodes and Validates the account information from body
// - Calls the service layer to reset the password
// - Returns the success message
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword, ErrInvalidCredentials, ErrDBEntryNotFound
// - storage: ErrDBStorageFailed
func (h *accountHandler) ResetPasswordConfirm(gc *gsk.Context) {
	var account *ds.Account

	err := gc.DecodeJSONBody(&account)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	resetToken := gc.QueryParam("token")
	password := account.Password

	err = h.authService.ResetPassword(resetToken, password)
	if err != nil {
		if errors.Is(err, svrerr.ErrInvalidToken) {
			gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
				"message": transport.INVALID_CREDENTIALS,
			})
			return
		}
		gc.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"message": transport.INTERNAL_SERVER_ERROR,
		})
		return
	}

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_CHANGED_PASSWORD,
	})
}
