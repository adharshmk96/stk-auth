package transport

import (
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
	"github.com/adharshmk96/stk/gsk"
)

var config = infra.GetConfig()

func GetSessionOrTokenFromCookie(ctx gsk.Context) (*http.Cookie, *http.Cookie, error) {
	sessionCookie, scerr := ctx.GetCookie(config.SESSION_COOKIE_NAME)
	sessionToken, sterr := ctx.GetCookie(config.JWT_SESSION_COOKIE_NAME)
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
