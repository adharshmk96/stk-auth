package routing

import (
	"github.com/adharshmk96/stk/gsk"
)

var webRouteGroups = []func(*gsk.RouteGroup){}
var apiRouteGroups = []func(*gsk.RouteGroup){}

func RegisterApiRoutes(routeGroup func(*gsk.RouteGroup)) {
	apiRouteGroups = append(apiRouteGroups, routeGroup)
}

func RegisterWebRoutes(routeGroup func(*gsk.RouteGroup)) {
	webRouteGroups = append(webRouteGroups, routeGroup)
}

func SetupApiRoutes(server *gsk.Server) {
	apiRoutes := server.RouteGroup("/api")

	for _, routeGroup := range apiRouteGroups {
		routeGroup(apiRoutes)
	}
}

func SetupTemplateRoutes(server *gsk.Server) {
	templateRoutes := server.RouteGroup("/")

	for _, routeGroup := range webRouteGroups {
		routeGroup(templateRoutes)
	}

}
