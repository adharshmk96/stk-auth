package transport

import (
	"net/http"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk-auth/pkg/svrerr"
)

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
	if err == svrerr.ErrDuplicateEntry {
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
	if err == svrerr.ErrDuplicateEntry {
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
