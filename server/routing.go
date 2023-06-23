package server

import (
	"github.com/adharshmk96/auth-server/pkg/http/handlers"
	"github.com/adharshmk96/stk"
)

func setupRoutes(server *stk.Server) {
	server.Post("/register", handlers.RegisterHandler)
}
