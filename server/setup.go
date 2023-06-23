package server

import "github.com/adharshmk96/stk"

func StartServer(port string) *stk.Server {

	serverConfig := &stk.ServerConfig{
		Port:           port,
		RequestLogging: true,
	}

	server := stk.NewServer(serverConfig)

	setupRoutes(server)

	rateLimiter := rateLimiter()
	server.Use(rateLimiter)

	server.Start()

	return server
}
