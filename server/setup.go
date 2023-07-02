package server

import (
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk/gsk"
)

func StartServer(port string) *gsk.Server {

	serverConfig := &gsk.ServerConfig{
		Port:           port,
		RequestLogging: true,
	}

	server := gsk.NewServer(serverConfig)

	infra.LoadDefaultConfig()

	setupRoutes(server)

	rateLimiter := rateLimiter()
	server.Use(rateLimiter)

	server.Start()

	return server
}
