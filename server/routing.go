package server

import (
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/infra/constants"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/storage/sqlite"
	"github.com/adharshmk96/stk/gsk"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/spf13/viper"
)

func setupRoutes(server gsk.Server) {

	connection := db.GetSqliteConnection(viper.GetString(constants.ENV_SQLITE_FILE))

	userStorage := sqlite.NewAccountStorage(connection)
	userService := services.NewAccountService(userStorage)
	userHandler := handlers.NewAccountHandler(userService)

	// User authentication
	server.Post("/api/auth/register", userHandler.RegisterUser)

	server.Post("/api/auth/session/login", userHandler.LoginUserSession)
	server.Post("/api/auth/token/login", userHandler.LoginUserToken)

	// server.Post("/api/auth/token/login", userHandler.LoginUserSessionToken) // issues access and refresh tokens(refresh expiry = loggedout)
	// server.Post("/api/auth/token/access/validate", userHandler.LoginUserSessionToken) // validates access token
	// server.Post("/api/auth/token/access/refresh", userHandler.LoginUserSessionToken) // issues new access token

	server.Get("/api/auth/session/user", userHandler.GetSessionUser)
	server.Get("/api/auth/session/user/token", userHandler.GetTokenUser)

	server.Post("/api/auth/logout", userHandler.LogoutUser)

	// Health check
	server.Get("/health", handlers.HealthCheckHandler)
}
