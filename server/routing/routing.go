package routing

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk/gsk"
)

func SetupAccountRoutes(apiRoutes *gsk.RouteGroup, authHandler entities.AuthenticationHandler) {
	apiAuth := apiRoutes.RouteGroup("/auth")

	apiAuth.Post("/register", authHandler.RegisterAccount)

	apiAuth.Post("/session/login", authHandler.LoginAccountSession)
	apiAuth.Post("/token/login", authHandler.LoginAccountToken)

	apiAuth.Get("/session/account", authHandler.GetSessionAccount)
	apiAuth.Get("/token/account", authHandler.GetTokenAccount)

	apiAuth.Post("/update/credentials", authHandler.ChangeCredentials)
	apiAuth.Post("/reset/password", authHandler.ResetPassword)
	apiAuth.Post("/reset/password/confirm", authHandler.ResetPasswordConfirm)

	apiAuth.Post("/logout", authHandler.LogoutAccount)

}

func SetupAdminRoutes(apiRoutes *gsk.RouteGroup, adminHandler entities.AdminHandler) {
	adminRoutes := apiRoutes.RouteGroup("/admin")

	adminRoutes.Get("/accounts", adminHandler.GetAccountList)
	adminRoutes.Get("/account", adminHandler.GetAccountDetails)

	adminRoutes.Post("/group", adminHandler.CreateGroup)
}
