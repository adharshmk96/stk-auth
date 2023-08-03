package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/entities"
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

// RegisterUser registers a new user
// - Decodes and Validates the user information from body
// - Calls the service layer to store the user information
// - Returns the user information
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword,
// - storage: ErrDBStorageFailed, ErrDBDuplicateEntry
func (h *authenticationHandler) RegisterUser(gc *gsk.Context) {
	var user *ds.User

	err := gc.DecodeJSONBody(&user)
	if err != nil {
		transport.HandleJsonDecodeError(err, gc)
		return
	}

	errorMessages := validator.ValidateRegistration(user)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, gc)
		return
	}

	createdUser, err := h.authService.CreateUser(user)
	if err != nil {
		transport.HandleRegistrationError(err, gc)
		return
	}

	response := transport.UserResponse{
		ID:        createdUser.ID.String(),
		Username:  createdUser.Username,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
		UpdatedAt: createdUser.UpdatedAt,
	}

	gc.Status(http.StatusCreated).JSONResponse(response)
}

// ChangeCredentials changes the password of the user
// - Decodes and Validates the user information from body
// - Calls the service layer to change the password
// - Returns the success message
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrHasingPassword, ErrInvalidCredentials, ErrDBEntryNotFound
// - storage: ErrDBStorageFailed
func (h *authenticationHandler) ChangeCredentials(gc *gsk.Context) {
	var credentials *transport.CredentialUpdateRequest

	err := gc.DecodeJSONBody(&credentials)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	user := credentials.Credentials

	err = h.authService.Authenticate(user)
	if err != nil {
		transport.HandleChangePasswordError(err, gc)
		return
	}

	updatedUser := credentials.NewCredentials

	err = h.authService.ChangePassword(updatedUser)
	if err != nil {
		transport.HandleChangePasswordError(err, gc)
		return
	}

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_CHANGED_PASSWORD,
	})
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
func (h *authenticationHandler) LoginUserSession(gc *gsk.Context) {
	var userLogin *ds.User

	err := gc.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, gc)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, gc)
		return
	}

	err = h.authService.Authenticate(userLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	sessionData, err := h.authService.CreateSession(userLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	userData, err := h.authService.GetUserByID(sessionData.UserID.String())
	if err != nil {
		transport.HandleGetUserError(err, gc)
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

	response := transport.UserResponse{
		ID:        userData.ID.String(),
		Username:  userData.Username,
		Email:     userData.Email,
		CreatedAt: userData.CreatedAt,
		UpdatedAt: userData.UpdatedAt,
	}

	gc.SetCookie(cookie)
	gc.Status(http.StatusOK).JSONResponse(response)
}

// LoginUserToken creates a new session for the user and sets the session id in cookie
// - Decodes and Validates the user information from body
// - Calls the service layer to authenticate, generate access and refresh tokens
// - Sets the session token in cookie
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed
// NOTE:
// - session token should not be exposed to client, it should be in httpOnly cookie
func (h *authenticationHandler) LoginUserToken(gc *gsk.Context) {
	var userLogin *ds.User

	err := gc.DecodeJSONBody(&userLogin)
	if err != nil {
		transport.HandleJsonDecodeError(err, gc)
		return
	}

	errorMessages := validator.ValidateLogin(userLogin)
	if len(errorMessages) > 0 {
		transport.HandleValidationError(errorMessages, gc)
		return
	}

	err = h.authService.Authenticate(userLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	// Generate Access Token
	userId := userLogin.ID.String()
	requestHost := gc.Request.Host

	atjwt, rtjwt, err := generateTokens(userId, requestHost, h.authService)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	atCookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
		Value:    atjwt,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		SameSite: sameSite,
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
	}

	rtCookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
		Value:    rtjwt,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		SameSite: sameSite,
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
	}

	response := gsk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	gc.SetCookie(atCookie)
	gc.SetCookie(rtCookie)
	gc.Status(http.StatusOK).JSONResponse(response)
}

func generateTokens(userId, requestHost string, svc entities.AuthenticationService) (string, string, error) {
	timeNow := time.Now()
	accessExpiry := timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_ACCESS_JWT_EXPIRATION_DURATION))
	refreshExpiry := timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_REFRESH_JWT_EXPIRATION_DURATION))

	atClaims := &entities.CustomClaims{
		UserID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			Issuer:    viper.GetString(constants.ENV_SERVER_DOMAIN),
			Audience:  jwt.ClaimStrings{requestHost},
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
		},
	}

	rtClaims := &entities.CustomClaims{
		UserID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId,
			Issuer:    viper.GetString(constants.ENV_SERVER_DOMAIN),
			Audience:  jwt.ClaimStrings{requestHost},
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
		},
	}

	atjwt, err := svc.GenerateJWT(atClaims)
	if err != nil {
		return "", "", err
	}

	rtjwt, err := svc.GenerateJWT(rtClaims)
	if err != nil {
		return "", "", err
	}
	return atjwt, rtjwt, nil
}

// GetSessionUser returns the user information from session id
// - Gets the session id from cookie
// - Calls the service layer to get the user information
// - Returns the user information
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidSession
// - storage: ErrDBStorageFailed
func (h *authenticationHandler) GetSessionUser(gc *gsk.Context) {
	sessionCookie, err := gc.GetCookie(viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
	if err != nil || sessionCookie == nil || sessionCookie.Value == "" {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	user, err := h.authService.GetUserBySessionId(sessionCookie.Value)
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

	response := transport.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	gc.Status(http.StatusOK).JSONResponse(response)
}

// GetTokenUser returns the user information from access token
// - Gets the session token from cookie
// - Calls the service layer to validate token and get the user information
// - Returns the user information
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidToken
// - storage: ErrDBStorageFailed
func (h *authenticationHandler) GetTokenUser(gc *gsk.Context) {
	// TODO split to validate and refresh ?
	accessTokenCookie, err := gc.GetCookie(viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
	if err != nil || accessTokenCookie == nil || accessTokenCookie.Value == "" {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	refreshToken := false
	claims, err := h.authService.ValidateJWT(accessTokenCookie.Value)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			refreshToken = true
		} else {
			if errors.Is(err, svrerr.ErrInvalidToken) {
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
	}
	// TODO: check token claims are logically valid

	userData, err := h.authService.GetUserByID(claims.UserID)
	if err != nil {
		transport.HandleGetUserError(err, gc)
		return
	}

	if refreshToken {
		refreshTokenCookie, err := gc.GetCookie(viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME))
		if err != nil || refreshTokenCookie == nil || refreshTokenCookie.Value == "" {
			gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
			return
		}

		rtClaims, err := h.authService.ValidateJWT(refreshTokenCookie.Value)
		if err != nil {
			if errors.Is(err, svrerr.ErrInvalidToken) || errors.Is(err, jwt.ErrTokenExpired) {
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

		userId := userData.ID.String()
		timeNow := time.Now()
		accessExpiry := timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_ACCESS_JWT_EXPIRATION_DURATION))

		if rtClaims.ExpiresAt.Time.Before(accessExpiry) {
			accessExpiry = rtClaims.ExpiresAt.Time
		}

		atClaims := &entities.CustomClaims{
			UserID: userId,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userId,
				Issuer:    viper.GetString(constants.ENV_SERVER_DOMAIN),
				IssuedAt:  jwt.NewNumericDate(timeNow),
				ExpiresAt: jwt.NewNumericDate(accessExpiry),
			},
		}

		accessToken, err := h.authService.GenerateJWT(atClaims)
		if err != nil {
			transport.HandleLoginError(err, gc)
			return
		}

		cookie := &http.Cookie{
			Name:     viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value:    accessToken,
			HttpOnly: true,
			Secure:   secureCookie,
			Path:     "/",
			SameSite: sameSite,
			Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
		}

		gc.SetCookie(cookie)
	}

	response := transport.UserResponse{
		ID:        userData.ID.String(),
		Username:  userData.Username,
		Email:     userData.Email,
		CreatedAt: userData.CreatedAt,
		UpdatedAt: userData.UpdatedAt,
	}

	gc.Status(http.StatusOK).JSONResponse(response)
}

// LogoutUser logs out the user
// - Gets the session id or session toekn from cookie
// - Calls the service layer to invalidate the session
// - Returns the success message
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidSession, ErrInvalidToken
// - storage: ErrDBStorageFailed
func (h *authenticationHandler) LogoutUser(gc *gsk.Context) {
	sessionCookie, refreshToken, err := transport.GetSessionOrTokenFromCookie(gc)
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	if sessionCookie != nil && sessionCookie.Value != "" {
		err := h.authService.LogoutUserBySessionId(sessionCookie.Value)
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
