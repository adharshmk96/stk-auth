package handlers

import "github.com/adharshmk96/stk"

func RegisterHandler(ctx *stk.Context) {
	ctx.Status(200).JSONResponse(stk.Map{
		"message": "Hello World",
	})
}
