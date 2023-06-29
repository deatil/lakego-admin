package route

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-extension/extension/controller"
)

// 路由
func Route(engine gin.IRouter) {
    // 扩展
    extController := new(controller.Extension)
    engine.GET("/extension", extController.Index)
    engine.GET("/extension/local", extController.Local)
    engine.POST("/extension/:name/install", extController.Inatll)
    engine.DELETE("/extension/:name/uninstall", extController.Uninstall)
    engine.PUT("/extension/:name/upgrade", extController.Upgrade)
    engine.PATCH("/extension/:name/sort", extController.Listorder)
    engine.PATCH("/extension/:name/enable", extController.Enable)
    engine.PATCH("/extension/:name/disable", extController.Disable)
}
