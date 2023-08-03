package routing

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk/gsk"
)

func SetupUserRoutes(apiRoutes *gsk.RouteGroup, authHandler entities.AuthenticationHandler) {
	apiAuth := apiRoutes.RouteGroup("/auth")

	apiAuth.Post("/register", authHandler.RegisterUser)

	apiAuth.Post("/session/login", authHandler.LoginUserSession)
	apiAuth.Post("/token/login", authHandler.LoginUserToken)

	apiAuth.Get("/session/user", authHandler.GetSessionUser)
	apiAuth.Get("/token/user", authHandler.GetTokenUser)

	apiAuth.Post("/update/credentials", authHandler.ChangeCredentials)

	apiAuth.Post("/logout", authHandler.LogoutUser)

}

func SetupAdminRoutes(apiRoutes *gsk.RouteGroup, adminHandler entities.AdminHandler) {
	adminRoutes := apiRoutes.RouteGroup("/admin")

	adminRoutes.Get("/users", adminHandler.GetUserList)
	adminRoutes.Get("/user", adminHandler.GetUserDetails)
}
