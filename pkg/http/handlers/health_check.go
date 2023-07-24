package handlers

import (
	"net/http"

	"github.com/adharshmk96/stk/gsk"
)

func HealthCheckHandler(ctx *gsk.Context) {
	ctx.Status(http.StatusOK).JSONResponse(gsk.Map{
		"status": "ok",
	})
}
