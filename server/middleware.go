package server

import (
	"time"

	"github.com/adharshmk96/stk"
	"github.com/adharshmk96/stk/middleware"
)

func rateLimiter() stk.Middleware {
	rateLimiter := middleware.NewRateLimiter(60, 10*time.Second)
	return rateLimiter.Middleware
}
