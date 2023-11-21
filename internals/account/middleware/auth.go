package middleware

import (
	"github.com/adharshmk96/stk-auth/internals/account/api/transport"
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk/gsk"
)

func IsAuthenticatedMiddleware(accountService domain.AccountService) gsk.Middleware {
	return func(next gsk.HandlerFunc) gsk.HandlerFunc {
		return func(gc *gsk.Context) {
			cookie, err := gc.Request.Cookie(transport.SESSION_COOKIE_NAME)
			if err != nil {
				gc.Status(401).JSONResponse(gsk.Map{
					"message": "unauthorized",
				})
				return
			}

			sessionToken := cookie.Value

			account, err := accountService.GetSessionAccount(sessionToken)
			if err != nil {
				gc.Status(401).JSONResponse(gsk.Map{
					"message": "unauthorized",
				})
				return
			}

			gc.Set("is_authenticated", true)
			gc.Set("account", account)

			next(gc)
		}
	}
}
