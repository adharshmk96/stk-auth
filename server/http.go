package server

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/adharshmk96/stk-auth/pkg/http/handlers"
	"github.com/adharshmk96/stk-auth/pkg/services"
	"github.com/adharshmk96/stk-auth/pkg/storage/account/sqlite"
	"github.com/adharshmk96/stk-auth/server/infra"
	"github.com/adharshmk96/stk-auth/server/infra/constants"
	svrmw "github.com/adharshmk96/stk-auth/server/middleware"
	"github.com/adharshmk96/stk-auth/server/routing"
	"github.com/adharshmk96/stk/gsk"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/adharshmk96/stk/pkg/middleware"
	"github.com/spf13/viper"
)

func StartHttpServer(port string) (*gsk.Server, chan bool) {

	logger := infra.GetLogger()

	serverConfig := &gsk.ServerConfig{
		Port:   port,
		Logger: logger,
	}

	server := gsk.New(serverConfig)

	rateLimiter := svrmw.RateLimiter()
	server.Use(rateLimiter)
	server.Use(middleware.RequestLogger)
	server.Use(middleware.CORS(middleware.CORSConfig{
		AllowAll: true,
	}))

	infra.LoadDefaultConfig()

	intializeServer(server)

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

func intializeServer(server *gsk.Server) {
	connection := db.GetSqliteConnection(viper.GetString(constants.ENV_SQLITE_FILE))

	// Initialize the account service
	authStorage := sqlite.NewAccountStorage(connection)
	authService := services.NewAuthenticationService(authStorage)

	accountHandler := handlers.NewAccountHandler(authService)
	adminHandler := handlers.NewAdminHandler(authService)

	// Health check
	server.Get("/health", handlers.HealthCheckHandler)

	apiRoutes := server.RouteGroup("/api")
	routing.SetupAccountRoutes(apiRoutes, accountHandler)
	routing.SetupAdminRoutes(apiRoutes, adminHandler)

	CreateAdmin(authService)
}
