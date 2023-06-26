package server

import (
	"github.com/adharshmk96/auth-server/pkg/http/handlers"
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/auth-server/pkg/storage/sqlite"
	"github.com/adharshmk96/stk"
)

func setupRoutes(server *stk.Server) {
	userStorage := sqlite.NewAccountStorage()
	userService := services.NewAccountService(userStorage)
	userHandler := handlers.NewAccountHandler(userService)

	server.Post("/api/auth/register", userHandler.RegisterUser)
	server.Post("/api/auth/session/login", userHandler.LoginUserSessionToken)
}
