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
	server.Post("/api/auth/register", userHandler.RegisterUser)

	server.Post("/api/auth/session/login", userHandler.LoginUserSession)
	server.Post("/api/auth/token/login", userHandler.LoginUserToken)

	server.Get("/api/auth/session/user", userHandler.GetSessionUser)
	server.Get("/api/auth/token/user", userHandler.GetTokenUser)

	server.Post("/api/auth/update/password", userHandler.ChangePassword)
	// server.Post("/api/auth/update/credentials", userHandler.ChangeCredentials) // maybe one route for all updates

	server.Post("/api/auth/logout", userHandler.LogoutUser)

	// Health check
	server.Get("/health", handlers.HealthCheckHandler)

	server.Static("/ui/*filepath", "./ui")
}
