package server

import (
	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/storage/sqlite"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	"github.com/adharshmk96/stk/gsk"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/spf13/viper"
)

func intializeServer(server gsk.Server) {

	connection := db.GetSqliteConnection(viper.GetString(constants.ENV_SQLITE_FILE))

	userStorage := sqlite.NewAccountStorage(connection)
	userService := services.NewUserManagementService(userStorage)
	userHandler := handlers.NewUserManagementHandler(userService)

	CreateAdmin(userService)

	setupRoutes(server, userHandler)
}

func setupRoutes(server gsk.Server, userHandler entities.UserManagmentHandler) {
	apiRoutes := server.RouteGroup("/api")
	apiAuth := apiRoutes.RouteGroup("/auth")

	apiAuth.Post("/register", userHandler.RegisterUser)

	apiAuth.Post("/session/login", userHandler.LoginUserSession)
	apiAuth.Post("/token/login", userHandler.LoginUserToken)

	apiAuth.Get("/session/user", userHandler.GetSessionUser)
	apiAuth.Get("/token/user", userHandler.GetTokenUser)

	apiAuth.Post("/update/credentials", userHandler.ChangeCredentials)

	apiAuth.Post("/logout", userHandler.LogoutUser)

	// Health check
	server.Get("/health", handlers.HealthCheckHandler)

	// server.Static("/ui/*filepath", "./ui")
}
