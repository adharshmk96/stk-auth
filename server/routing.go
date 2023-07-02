package server

import (
	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/storage/sqlite"
	"github.com/adharshmk96/stk/gsk"
)

func setupRoutes(server *gsk.Server) {
	userStorage := sqlite.NewAccountStorage()
	userService := services.NewAccountService(userStorage)
	userHandler := handlers.NewAccountHandler(userService)

	server.Post("/api/auth/register", userHandler.RegisterUser)

	server.Post("/api/auth/session/login", userHandler.LoginUserSession)
	server.Post("/api/auth/session/login/token", userHandler.LoginUserSessionToken)

	server.Get("/api/auth/session/user", userHandler.GetSessionUser)
	server.Get("/api/auth/session/user/token", userHandler.GetSessionTokenUser)

	server.Post("/api/auth/logout", userHandler.LogoutUser)
}
