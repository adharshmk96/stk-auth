package transport

import (
	"errors"
	"net/http"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/pkg/infra/config"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

func GetSessionOrTokenFromCookie(ctx stk.Context) (*http.Cookie, *http.Cookie, error) {
	sessionCookie, scerr := ctx.GetCookie(config.SESSION_COOKIE_NAME)
	sessionToken, sterr := ctx.GetCookie(config.JWT_SESSION_COOKIE_NAME)
	if (scerr != nil && sterr != nil) || (scerr == nil && sessionCookie.Value == "") || (sterr == nil && sessionToken.Value == "") {
		return nil, nil, errors.New("Unauthorized")
	}
	return sessionCookie, sessionToken, nil
}

func HandleJsonDecodeError(err error, ctx stk.Context) {
	if err == stk.ErrInvalidJSON {
		ctx.Status(http.StatusBadRequest).JSONResponse(stk.Map{
			"error": INVALID_BODY,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(stk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleRegistrationError(err error, ctx stk.Context) {
	if err == svrerr.ErrDBDuplicateEntry {
		ctx.Status(http.StatusConflict).JSONResponse(stk.Map{
			"error": USER_EXISTS,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(stk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleLoginError(err error, ctx stk.Context) {
	if err == svrerr.ErrDBDuplicateEntry {
		ctx.Status(http.StatusConflict).JSONResponse(stk.Map{
			"error": SESSION_EXISTS,
		})
	} else if err == svrerr.ErrInvalidCredentials {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"error": INVALID_CREDENTIALS,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(stk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}

func HandleValidationError(errorMessages map[string]string, ctx stk.Context) {
	ctx.Status(http.StatusBadRequest).JSONResponse(stk.Map{
		"error":   VALIDATION_FAILED,
		"details": errorMessages,
	})
}

func HandleLogoutError(err error, ctx stk.Context) {
	if err == svrerr.ErrInvalidSession {
		ctx.Status(http.StatusUnauthorized).JSONResponse(stk.Map{
			"error": ERROR_UNAUTHORIZED,
		})
	} else {
		ctx.Status(http.StatusInternalServerError).JSONResponse(stk.Map{
			"error": INTERNAL_SERVER_ERROR,
		})
	}
}
