package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

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
func (h *userManagmentHandler) LoginUserSession(gc gsk.Context) {
	var userLogin *entities.Account

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

	err = h.userService.Authenticate(userLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	sessionData, err := h.userService.CreateSession(userLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
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
func (h *userManagmentHandler) LoginUserToken(gc gsk.Context) {
	var userLogin *entities.Account

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

	err = h.userService.Authenticate(userLogin)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	// Generate Access Token
	userId := userLogin.ID.String()
	requestHost := gc.GetRequest().Host

	atjwt, rtjwt, err := generateTokens(userId, requestHost, h.userService)
	if err != nil {
		transport.HandleLoginError(err, gc)
		return
	}

	secureCookie := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
	atCookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
		Value:    atjwt,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
	}

	rtCookie := &http.Cookie{
		Name:     viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME),
		Value:    rtjwt,
		HttpOnly: true,
		Secure:   secureCookie,
		Path:     "/",
		Domain:   viper.GetString(constants.ENV_SERVER_DOMAIN),
	}

	response := gsk.Map{
		"message": transport.SUCCESS_LOGIN,
	}

	gc.SetCookie(atCookie)
	gc.SetCookie(rtCookie)
	gc.Status(http.StatusOK).JSONResponse(response)
}

func generateTokens(userId, requestHost string, svc entities.UserManagementService) (string, string, error) {
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
func (h *userManagmentHandler) GetSessionUser(gc gsk.Context) {
	sessionCookie, err := gc.GetCookie(viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
	if err != nil || sessionCookie == nil || sessionCookie.Value == "" {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	user, err := h.userService.GetUserBySessionId(sessionCookie.Value)
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
func (h *userManagmentHandler) GetTokenUser(gc gsk.Context) {
	// TODO split to validate and refresh ?
	accessTokenCookie, err := gc.GetCookie(viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
	if err != nil || accessTokenCookie == nil || accessTokenCookie.Value == "" {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	refreshToken := false
	claims, err := h.userService.ValidateJWT(accessTokenCookie.Value)
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

	userData, err := h.userService.GetUserByID(claims.UserID)
	if err != nil {
		transport.HandleGetUserError(err, gc)
		return
	}

	if refreshToken {
		// TODO: check if refresh token is valid
		refreshTokenCookie, err := gc.GetCookie(viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME))
		if err != nil || refreshTokenCookie == nil || refreshTokenCookie.Value == "" {
			gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
				"message": transport.ERROR_UNAUTHORIZED,
			})
			return
		}

		rtClaims, err := h.userService.ValidateJWT(refreshTokenCookie.Value)
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

		accessToken, err := h.userService.GenerateJWT(atClaims)
		if err != nil {
			transport.HandleLoginError(err, gc)
			return
		}

		secureCookie := viper.GetString(constants.ENV_SERVER_MODE) == constants.SERVER_PROD_MODE
		cookie := &http.Cookie{
			Name:     viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME),
			Value:    accessToken,
			HttpOnly: true,
			Secure:   secureCookie,
			Path:     "/",
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
func (h *userManagmentHandler) LogoutUser(gc gsk.Context) {
	sessionCookie, refreshToken, err := transport.GetSessionOrTokenFromCookie(gc)
	if err != nil {
		gc.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"message": transport.ERROR_UNAUTHORIZED,
		})
		return
	}

	if sessionCookie != nil && sessionCookie.Value != "" {
		err := h.userService.LogoutUserBySessionId(sessionCookie.Value)
		if err != nil {
			transport.HandleLogoutError(err, gc)
			return
		}
	} else {
		_, err := h.userService.ValidateJWT(refreshToken.Value)
		if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
			transport.HandleLogoutError(err, gc)
			return
		}

	}

	sessionCookieName := viper.GetString(constants.ENV_SESSION_COOKIE_NAME)
	atCookieName := viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME)
	rtCookieName := viper.GetString(constants.ENV_JWT_REFRESH_TOKEN_COOKIE_NAME)

	newSessionCookie := &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		MaxAge: -1,
	}

	atCookie := &http.Cookie{
		Name:   atCookieName,
		Value:  "",
		MaxAge: -1,
	}

	rtCookie := &http.Cookie{
		Name:   rtCookieName,
		Value:  "",
		MaxAge: -1,
	}

	gc.SetCookie(newSessionCookie)
	gc.SetCookie(atCookie)
	gc.SetCookie(rtCookie)

	gc.Status(http.StatusOK).JSONResponse(gsk.Map{
		"message": transport.SUCCESS_LOGOUT,
	})
}
