package handler

import (
	"net/http"

	"github.com/adharshmk96/stk-auth/internals/account/api/transport"
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk/gsk"
)

func (h *accountHandler) AccountDetails(gc *gsk.Context) {

	isAuth := gc.Get("is_authenticated")
	if isAuth == nil {
		gc.Status(401).JSONResponse(gsk.Map{
			"error":   "unauthorized",
			"message": "user is not authenticated",
		})
		return
	}

	account := gc.Get("account").(*domain.Account)
	if account == nil {
		gc.Status(401).JSONResponse(gsk.Map{
			"error":   "unauthorized",
			"message": "error getting account",
		})
		return
	}

	responseData := transport.AccountData{
		ID:        account.ID.String(),
		Email:     account.Email,
		FirstName: account.FirstName,
		LastName:  account.LastName,
	}

	gc.Status(200).JSONResponse(gsk.Map{
		"user": responseData,
	})
}

func (h *accountHandler) Logout(gc *gsk.Context) {
	cookie, err := gc.GetCookie(transport.SESSION_COOKIE_NAME)
	if err != nil {
		gc.Status(401).JSONResponse(gsk.Map{
			"message": "unauthorized",
		})
		return
	}

	sessionToken := cookie.Value

	err = h.service.EndSession(sessionToken)
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"message": "error deleting session",
		})
		return
	}

	sessionCookie := &http.Cookie{
		Name:     transport.SESSION_COOKIE_NAME,
		Value:    "",
		HttpOnly: true,
		Path:     "/",
	}

	gc.SetCookie(sessionCookie)

	gc.Status(200).JSONResponse(gsk.Map{
		"message": "success",
	})
}
