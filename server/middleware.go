package server

import (
	"time"

	"github.com/adharshmk96/stk/gsk"
	"github.com/adharshmk96/stk/pkg/middleware"
)

func rateLimiter() gsk.Middleware {
	config := middleware.RateLimiterConfig{
		RequestsPerInterval: 60,
		Interval:            10 * time.Second,
	}

	rateLimiter := middleware.NewRateLimiter(config)
	return rateLimiter.Middleware
}
