package route

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

// 路由
func AddRoute(f func(rg *router.RouterGroup)) {
    // 路由
    engine := router.NewRoute().Get()

    // 配置
    conf := config.New("admin")

    // 后台路由及设置中间件
    m := router.GetMiddlewares(conf.GetString("Route.Middleware"))

    // 路由
    admin := engine.Group(conf.GetString("Route.Prefix"))
    {
        admin.Use(m...)
        {
            f(admin)
        }
    }
}

