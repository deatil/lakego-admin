package bootstrap

import (
	"lakego-admin/lakego/app"
	"lakego-admin/lakego/provider"
	"lakego-admin/admin/provider/route"
	"lakego-admin/admin/provider/middleware"
)


func Start() {
	app := app.New()

	// 中间件，需在路由之前
	middlewareProvider := &middleware.MiddlewareProvider{}
	app.Register(func() provider.ServiceProvider {
		return middlewareProvider
	})

	// 路由
	routeProvider := &route.RouteProvider{}
	app.Register(func() provider.ServiceProvider {
		return routeProvider
	})

	app.Run()
}
