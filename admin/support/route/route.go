package route

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/http/route"
    router "lakego-admin/lakego/route"
)

// 路由
func AddRoute(f func(rg *gin.RouterGroup)) {
    // 路由
    engine := router.New().Get()

    // 配置
    conf := config.New("admin")

    // 后台路由及设置中间件
    m := route.GetMiddlewares(conf.GetString("Route.Middleware"))

    // 路由
    admin := engine.Group(conf.GetString("Route.Prefix"))
    {
        admin.Use(m...)
        {
            f(admin)
        }
    }
}

