package account

import (
	"github.com/adharshmk96/stk-auth/internals/account/api/handler"
	"github.com/adharshmk96/stk-auth/internals/account/domain"
	"github.com/adharshmk96/stk-auth/internals/account/middleware"
	"github.com/adharshmk96/stk-auth/internals/account/service"
	"github.com/adharshmk96/stk-auth/internals/account/storage"
	"github.com/adharshmk96/stk-auth/internals/account/web"
	"github.com/adharshmk96/stk-auth/server/infra/db"
	"github.com/adharshmk96/stk/gsk"
)

var (
	accountStorage domain.AccountStorage
	accountService domain.AccountService
	accountHandler domain.AccountHandlers
)

func initializeAccountHandler() domain.AccountHandlers {
	conn := db.GetSqliteConnection()

	accountStorage = storage.NewSqliteRepo(conn)
	accountService = service.NewAccountService(accountStorage)
	accountHandler = handler.NewAccountHandler(accountService)

	return accountHandler
}

func SetupApiRoutes(rg *gsk.RouteGroup) {
	accountHandler := initializeAccountHandler()

	oauthRoutes := rg.RouteGroup("/oauth")

	oauthRoutes.Get("/google", accountHandler.LoginWithGoogle)
	oauthRoutes.Get("/google/callback", accountHandler.LoginWithGoogleCallback)

	accountRoutes := rg.RouteGroup("/account")

	accountRoutes.Use(middleware.IsAuthenticatedMiddleware(accountService))

	accountRoutes.Get("/me", accountHandler.AccountDetails)
	accountRoutes.Get("/logout", accountHandler.Logout)

}

func SetupWebRoutes(rg *gsk.RouteGroup) {
	rg.Get("/account", web.HomeHandler)
}
