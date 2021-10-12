package route

import (
    "github.com/gin-gonic/gin"

    "app/example/controller"
)

/**
 * 路由
 */
func Route(engine *gin.RouterGroup) {
    // 例子
    indexController := new(controller.Index)
    engine.GET("/example/index", indexController.Index)
}
