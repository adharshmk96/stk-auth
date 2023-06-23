package server

import (
	"github.com/adharshmk96/auth-server/pkg/http/handlers"
	"github.com/adharshmk96/auth-server/pkg/services"
	"github.com/adharshmk96/auth-server/pkg/storage/sqlite"
	"github.com/adharshmk96/stk"
)

func setupRoutes(server *stk.Server) {
	userStorage := sqlite.NewUserStorage()
	userService := services.NewUserService(userStorage)
	userHandler := handlers.NewUserHandler(userService)

	server.Post("/auth/register", userHandler.RegisterUser)
	server.Get("/auth/user/:id", userHandler.GetUserByID)
}
