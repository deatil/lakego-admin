package route

import (
    "github.com/gin-gonic/gin"

    "extension/lakego/demo/controller"
)

/**
 * 常规 gin 路由
 */
func GinRoute(engine gin.IRouter) {
    engine.GET("/demo", func(ctx *gin.Context) {
        ctx.JSON(200, gin.H{
            "data": "demo 显示信息",
        })
    })
}

/**
 * 后台路由
 */
func AdminRoute(engine gin.IRouter) {
    // 扩展路由
    indexController := new(controller.Index)
    engine.GET("/demo", indexController.Index)
    engine.GET("/demo/:id", indexController.Detail)
    engine.DELETE("/demo/:id", indexController.Delete)
}
