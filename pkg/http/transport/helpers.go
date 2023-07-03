package transport

import (
	"net/http"
	"strings"

	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
	"github.com/spf13/viper"
)

func ParseRemoteAddress(remoteAddr string) (ip, port string) {
	ip = remoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
		port = remoteAddr[colonIndex+1:]
	}
	return ip, port
}

func GetSessionOrTokenFromCookie(ctx gsk.Context) (*http.Cookie, *http.Cookie, error) {
	sessionCookie, scerr := ctx.GetCookie(viper.GetString(constants.ENV_SESSION_COOKIE_NAME))
	sessionToken, sterr := ctx.GetCookie(viper.GetString(constants.ENV_JWT_ACCESS_TOKEN_COOKIE_NAME))
	if (scerr != nil && sterr != nil) || (scerr == nil && sessionCookie.Value == "") || (sterr == nil && sessionToken.Value == "") {
		return nil, nil, svrerr.ErrInvalidCredentials
	}
	return sessionCookie, sessionToken, nil
}

func HandleJsonDecodeError(err error, ctx gsk.Context) {
	if err == gsk.ErrInvalidJSON {
		ctx.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"error": INVALID_BODY,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleRegistrationError(err error, ctx gsk.Context) {
	if err == svrerr.ErrDBDuplicateEntry {
		ctx.Status(http.StatusConflict).JSONResponse(gsk.Map{
			"error": USER_EXISTS,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleLoginError(err error, ctx gsk.Context) {
	if err == svrerr.ErrDBDuplicateEntry {
		ctx.Status(http.StatusConflict).JSONResponse(gsk.Map{
			"error": SESSION_EXISTS,
		})
	} else if err == svrerr.ErrInvalidCredentials {
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"error": INVALID_CREDENTIALS,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleValidationError(errorMessages map[string]string, ctx gsk.Context) {
	ctx.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
		"error":   VALIDATION_FAILED,
		"details": errorMessages,
	})
}

func HandleLogoutError(err error, ctx gsk.Context) {
	if err == svrerr.ErrInvalidToken {
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"error": ERROR_UNAUTHORIZED,
		})
	}
	if err == svrerr.ErrInvalidSession {
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"error": ERROR_UNAUTHORIZED,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleGetUserError(err error, ctx gsk.Context) {
	switch err {
	case svrerr.ErrDBEntryNotFound, svrerr.ErrInvalidSession:
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"error": ERROR_UNAUTHORIZED,
		})
	case svrerr.ErrInvalidCredentials:
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"error": INVALID_CREDENTIALS,
		})
	default:
		ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleChangePasswordError(err error, ctx gsk.Context) {
	switch err {
	case svrerr.ErrInvalidCredentials:
		ctx.Status(http.StatusUnauthorized).JSONResponse(gsk.Map{
			"error": INVALID_CREDENTIALS,
		})
	default:
		ctx.Status(http.StatusInternalServerError).JSONResponse(gsk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}
