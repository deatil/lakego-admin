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
    engine.POST("/extension/install", adminController.Inatll)
    engine.DELETE("/extension/uninstall", extController.Uninstall)
    engine.PUT("/extension/upgrade", adminController.Upgrade)
    engine.PATCH("/extension/enable", adminController.Enable)
    engine.PATCH("/extension/disable", adminController.Disable)
}
