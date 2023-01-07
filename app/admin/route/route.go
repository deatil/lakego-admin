package route

import (
    "github.com/gin-gonic/gin"

    admin_controller "app/admin/controller"
)

/**
 * 路由
 */
func Route(engine gin.IRouter) {
    // 路由
    indexController := new(admin_controller.Index)
    engine.GET("/index", indexController.Index)
}
