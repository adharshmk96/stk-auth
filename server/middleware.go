package server

import (
	"time"

	"github.com/adharshmk96/stk/gsk"
	"github.com/adharshmk96/stk/pkg/middleware"
)

func rateLimiter() gsk.Middleware {
	rateLimiter := middleware.NewRateLimiter(60, 10*time.Second)
	return rateLimiter.Middleware
}
