package route

import (
    "github.com/gin-gonic/gin"

    index_controller "app/index/controller"
)

/**
 * 路由
 */
func Route(engine gin.IRouter) {
    // 路由
    indexController := new(index_controller.Index)
    engine.GET("/", indexController.Index)
}
