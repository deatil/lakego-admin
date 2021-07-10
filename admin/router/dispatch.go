package router

import (
    "github.com/gin-gonic/gin"
    
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/http/route"
)

/**
 * 后台路由及设置中间件
 */
func Dispatch(engine *gin.Engine) {
    // 中间件
    m := route.GetMiddlewares(config.New("admin").GetString("Route.Middleware"))
    
    engine.Use(m...)
    {
        admin := engine.Group(config.New("admin").GetString("Route.Group")) 
        {
            Route(admin)
        }
    }
}
