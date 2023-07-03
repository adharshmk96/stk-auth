package server

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk/gsk"
)

func StartHttpServer(port string) (gsk.Server, chan bool) {

	logger := infra.GetLogger()

	serverConfig := &gsk.ServerConfig{
		Port:           port,
		RequestLogging: true,
		Logger:         logger,
	}

	server := gsk.NewServer(serverConfig)

	infra.LoadDefaultConfig()

	setupRoutes(server)

	rateLimiter := rateLimiter()
	server.Use(rateLimiter)

	server.Start()

	// graceful shutdown
	done := make(chan bool)

	// A go routine that listens for os signals
	// it will block until it receives a signal
	// once it receives a signal, it will shutdown close the done channel
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		if err := server.Shutdown(); err != nil {
			logger.Error(err)
		}

		close(done)
	}()

	return server, done
}
