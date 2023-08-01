package server

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/storage/user/sqlite"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/spf13/viper"
)

func intializeServer(server *gsk.Server) {
	connection := db.GetSqliteConnection(viper.GetString(constants.ENV_SQLITE_FILE))

	// Initialize the user service
	userStorage := sqlite.NewAccountStorage(connection)
	userService := services.NewAuthenticationService(userStorage)
	userHandler := handlers.NewUserManagementHandler(userService)

	// Initialize the admin service
	adminService := services.NewAdminService(userStorage)
	adminHandler := handlers.NewAdminHandler(adminService)

	// Health check
	server.Get("/health", handlers.HealthCheckHandler)

	apiRoutes := server.RouteGroup("/api")
	setupUserRoutes(apiRoutes, userHandler)
	setupAdminRoutes(apiRoutes, adminHandler)

	CreateAdmin(userService)
}

func setupUserRoutes(apiRoutes *gsk.RouteGroup, authHandler entities.AuthenticationHandler) {
	apiAuth := apiRoutes.RouteGroup("/auth")

	apiAuth.Post("/register", authHandler.RegisterUser)

	apiAuth.Post("/session/login", authHandler.LoginUserSession)
	apiAuth.Post("/token/login", authHandler.LoginUserToken)

	apiAuth.Get("/session/user", authHandler.GetSessionUser)
	apiAuth.Get("/token/user", authHandler.GetTokenUser)

	apiAuth.Post("/update/credentials", authHandler.ChangeCredentials)

	apiAuth.Post("/logout", authHandler.LogoutUser)

}

func setupAdminRoutes(apiRoutes *gsk.RouteGroup, adminHandler entities.AdminHandler) {
	adminRoutes := apiRoutes.RouteGroup("/admin")

	adminRoutes.Get("/users", adminHandler.GetUserList)
	adminRoutes.Get("/user", adminHandler.GetUserDetails)
}
