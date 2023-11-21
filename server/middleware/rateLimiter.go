package middleware

import (
	"time"

	"github.com/adharshmk96/stk/gsk"
	gskmw "github.com/adharshmk96/stk/pkg/middleware"
)

func RateLimiter() gsk.Middleware {
	rlConfig := gskmw.RateLimiterConfig{
		RequestsPerInterval: 10,
		Interval:            60 * time.Second,
	}
	rateLimiter := gskmw.NewRateLimiter(rlConfig)
	return rateLimiter.Middleware
}
