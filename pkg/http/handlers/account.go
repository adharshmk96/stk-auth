package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

// RegisterUser registers a new user
// - Decodes and Validates the user information from body
// - Calls the service layer to store the user information
// - Returns the user information
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
func (h *accountHandler) RegisterUser(ctx gsk.Context) {
	var user *entities.Account

	err := ctx.DecodeJSONBody(&user)
	if err != nil {
		transport.HandleJsonDecodeError(err, ctx)
		return
	}

	errorMessages := validator.ValidateRegistration(user)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, ctx)
		return
	}

	createdUser, err := h.userService.CreateUser(user)
	if err != nil {
		transport.HandleRegistrationError(err, ctx)
		return
	}

	response := transport.UserResponse{
		ID:        createdUser.ID.String(),
		Username:  createdUser.Username,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
		UpdatedAt: createdUser.UpdatedAt,
	}

	ctx.Status(http.StatusCreated).JSONResponse(response)
}

// LoginUserSession creates a new session for the user and sets the session id in cookie
// - Decodes and Validates the user information from body
// - Calls the service layer to authenticate and store the session information
// - Sets the session id in cookie
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed
// NOTE:
// - session id should not be exposed to client, it should be in httpOnly cookie
func (h *accountHandler) LoginUserSession(ctx gsk.Context) {
	var userLogin *entities.Account

	err := ctx.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, ctx)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, ctx)
		return
	}

	err = h.userService.Authenticate(userLogin)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	sessionData, err := h.userService.CreateSession(userLogin)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	secureCookie := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_SESSION_COOKIE_NAME),
		Value:    sessionData.SessionID,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
	}

	response := gsk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	ctx.SetCookie(cookie)
	ctx.Status(http.StatusOK).JSONResponse(response)
}

// LoginUserSessionToken creates a new session for the user and sets the session id in cookie
// - Decodes and Validates the user information from body
// - Calls the service layer to authenticate, store the session information and generate jwt token with session id as claim
// - Sets the session token in cookie
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed
// NOTE:
// - session token should not be exposed to client, it should be in httpOnly cookie
func (h *accountHandler) LoginUserSessionToken(ctx gsk.Context) {
	var userLogin *entities.Account

	err := ctx.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, ctx)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, ctx)
		return
	}

	err = h.userService.Authenticate(userLogin)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	sessionData, err := h.userService.CreateSession(userLogin)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	userId := userLogin.ID.String()
	sessionId := sessionData.SessionID

	timeNow := time.Now()

	claims := &entities.CustomClaims{
		SessionID: sessionId,
		UserID:    userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			Issuer:    viper.GetString(constants.ENV_JWT_SUBJECT),
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_JWT_EXPIRATION_DURATION))),
		},
	}

	jwt, err := h.userService.GenerateJWT(claims)
	if err != nil {
		transport.HandleLoginError(err, ctx)
		return
	}

	secureCookie := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
		Value:    jwt,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
	}

	response := gsk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	ctx.SetCookie(cookie)
	ctx.Status(http.StatusOK).JSONResponse(response)
}

// GetSessionUser returns the user information from session id
// - Gets the session id from cookie
// - Calls the service layer to get the user information
// - Returns the user information
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed
func (h *accountHandler) GetSessionUser(ctx gsk.Context) {
	sessionCookie, err := ctx.GetCookie(viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
	if err != nil || sessionCookie == nil || sessionCookie.Value == "" {
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	user, err := h.userService.GetUserBySessionId(sessionCookie.Value)
	if err != nil {
		if err == svrerr.ErrInvalidSession {
			ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
		} else {
			ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
				"message": transport.INTERNAL_SERVER_ERROR,
			})
		}
		return
	}

	response := transport.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	ctx.Status(http.StatusOK).JSONResponse(response)
}

// GetSessionTokenUser returns the user information from session token
// - Gets the session token from cookie
// - Calls the service layer to validate token and get the user information
// - Returns the user information
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidToken
// - storage: ErrDBStorageFailed
func (h *accountHandler) GetSessionTokenUser(ctx gsk.Context) {
	sessionCookie, err := ctx.GetCookie(viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME))
	if err != nil || sessionCookie == nil || sessionCookie.Value == "" {
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	refreshToken := false
	claims, err := h.userService.ValidateJWT(sessionCookie.Value)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			refreshToken = true
		} else {
			if err == svrerr.ErrInvalidToken {
				ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
					"message": transport.ERROR_UNAUTHORIZED,
				})
			} else {
				ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
					"message": transport.INTERNAL_SERVER_ERROR,
				})
			}
			return
		}
	}
	// TODO: check token claims are logically valid

	userData, err := h.userService.GetUserBySessionId(claims.SessionID)
	if err != nil {
		transport.HandleGetUserError(err, ctx)
		return
	}

	if refreshToken {
		userId := userData.ID.String()
		sessionId := claims.SessionID
		timeNow := time.Now()

		claims := &entities.CustomClaims{
			SessionID: sessionId,
			UserID:    userId,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userId,
				Issuer:    viper.GetString(constants.ENV_JWT_SUBJECT),
				IssuedAt:  jwt.NewNumericDate(timeNow),
				ExpiresAt: jwt.NewNumericDate(timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_JWT_EXPIRATION_DURATION))),
			},
		}

		jwt, err := h.userService.GenerateJWT(claims)
		if err != nil {
			transport.HandleLoginError(err, ctx)
			return
		}

		secureCookie := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
		cookie := &http.Cookie{
			Name:     viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME),
			Value:    jwt,
			HttpOnly: true,
			Secure:   secureCookie,
			Path:     "/",
			Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
		}

		ctx.SetCookie(cookie)
	}

	response := transport.UserResponse{
		ID:        userData.ID.String(),
		Username:  userData.Username,
		Email:     userData.Email,
		CreatedAt: userData.CreatedAt,
		UpdatedAt: userData.UpdatedAt,
	}

	ctx.Status(http.StatusOK).JSONResponse(response)
}

// LogoutUser logs out the user
// - Gets the session id or session toekn from cookie
// - Calls the service layer to invalidate the session
// - Returns the success message
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidSession, ErrInvalidToken
// - storage: ErrDBStorageFailed
func (h *accountHandler) LogoutUser(ctx gsk.Context) {
	sessionCookie, sessionToken, err := transport.GetSessionOrTokenFromCookie(ctx)
	if err != nil {
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	var cookieName string
	if sessionCookie != nil && sessionCookie.Value != "" {
		err := h.userService.LogoutUserBySessionId(sessionCookie.Value)
		if err != nil {
			transport.HandleLogoutError(err, ctx)
			return
		}
		cookieName = viper.GetString(constants.ENV_SESSION_COOKIE_NAME)
	} else {
		claims, err := h.userService.ValidateJWT(sessionToken.Value)
		if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
			transport.HandleLogoutError(err, ctx)
			return
		}

		err = h.userService.LogoutUserBySessionId(claims.SessionID)
		if err != nil {
			transport.HandleLogoutError(err, ctx)
			return
		}
		cookieName = viper.GetString(constants.ENV_JWT_SESSION_COOKIE_NAME)
	}

	secureCookie := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 0, -1),
	}

	ctx.SetCookie(cookie)

	ctx.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_LOGOUT,
	})
}
