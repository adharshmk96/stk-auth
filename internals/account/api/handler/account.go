package handler

import "github.com/adharshmk96/stk/gsk"

func (h *accountHandler) AccountDetails(gc *gsk.Context) {

	cookie, err := gc.GetCookie("session")
	if err != nil {
		gc.Status(401).JSONResponse(gsk.Map{
			"message": "Unauthorized",
		})
		return
	}

	account, err := h.service.GetSessionAccount(cookie.Value)
	if err != nil {
		gc.Status(401).JSONResponse(gsk.Map{
			"message": "Unauthorized",
		})
		return
	}

	gc.Status(200).JSONResponse(gsk.Map{
		"user": account,
	})
}
