package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk-auth/pkg/http/validator"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

// TODO: Change the logic ?
// There should be only one token ( expiry 1 hour )
// If the token is recently expired, then generate new token
// Otherwise invalidate the session and ask the user to login again

// LoginAccountToken creates a new session for the account and sets the session id in cookie
// - Decodes and Validates the account information from body
// - Calls the service layer to authenticate, generate access and refresh tokens
// - Sets the session token in cookie
// ERRORS:
// - handler: ErrJsonDecodeFailed, ErrValidationFailed
// - service: ErrInvalidCredentials
// - storage: ErrDBStorageFailed
// NOTE:
// - session token should not be exposed to client, it should be in httpOnly cookie
func (h *accountHandler) LoginAccountToken(gc *gsk.Context) {
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

	// Generate Access Token
	accountId := accountLogin.ID.String()
	requestHost := gc.Request.Host

	atjwt, rtjwt, err := generateTokens(accountId, requestHost, h.authService)
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

func generateTokens(accountId, requestHost string, svc entities.AuthenticationService) (string, string, error) {
	timeNow := time.Now()
	accessExpiry := timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_ACCESS_JWT_EXPIRATION_DURATION))
	refreshExpiry := timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_REFRESH_JWT_EXPIRATION_DURATION))

	atClaims := &entities.CustomClaims{
		AccountID: accountId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   accountId,
			Issuer:    viper.GetString(constants.ENV_SERVER_DOMAIN),
			Audience:  jwt.ClaimStrings{requestHost},
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
		},
	}

	rtClaims := &entities.CustomClaims{
		AccountID: accountId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   accountId,
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

// GetTokenAccount returns the account information from access token
// - Gets the session token from cookie
// - Calls the service layer to validate token and get the account information
// - Returns the account information
// ERRORS:
// - handler: cookie_error
// - service: ErrInvalidToken
// - storage: ErrDBStorageFailed
func (h *accountHandler) GetTokenAccount(gc *gsk.Context) {
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

	accountData, err := h.authService.GetAccountByID(claims.AccountID)
	if err != nil {
		transport.HandleGetAccountError(err, gc)
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

		accountId := accountData.ID.String()
		timeNow := time.Now()
		accessExpiry := timeNow.Add(time.Minute * viper.GetDuration(constants.ENV_ACCESS_JWT_EXPIRATION_DURATION))

		if rtClaims.ExpiresAt.Time.Before(accessExpiry) {
			accessExpiry = rtClaims.ExpiresAt.Time
		}

		atClaims := &entities.CustomClaims{
			AccountID: accountId,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   accountId,
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

	response := transport.AccountResponse{
		ID:        accountData.ID.String(),
		Username:  accountData.Username,
		Email:     accountData.Email,
		CreatedAt: accountData.CreatedAt,
		UpdatedAt: accountData.UpdatedAt,
	}

	gc.Status(http.StatusOK).JSONResponse(response)
}
