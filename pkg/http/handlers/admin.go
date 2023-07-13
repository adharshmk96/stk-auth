package handlers

import (
	"github.com/adharshmk96/stk/gsk"
)

func (h *authenticationHandler) GetUserList(gc gsk.Context) {
	limit := gc.QueryParam("limit")
	offset := gc.QueryParam("offset")

	userList := gsk.Map{
		"limit":  limit,
		"offset": offset,
	}
	// userList, err := h.userService.GetUserList(limit, offset)
	// if err != nil {
	// 	gc.Status(500).JSONResponse(gsk.Map{
	// 		"error": "internal server error",
	// 	})
	// 	return
	// }

	gc.Status(200).JSONResponse(userList)
}
