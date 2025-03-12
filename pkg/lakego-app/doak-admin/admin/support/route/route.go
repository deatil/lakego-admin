package route

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade"
)

// 路由
func AddRoute(f func(rg *router.RouterGroup)) {
    // 路由
    engine := router.DefaultRoute().Get()

    // 配置
    conf := facade.Config("admin")

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

