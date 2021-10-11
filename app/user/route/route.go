package route

import (
    "github.com/gin-gonic/gin"

    "app/user/controller"
)

/**
 * 路由
 */
func Route(engine *gin.RouterGroup) {
    // 首页
    indexController := new(controller.Index)
    engine.GET("/user/index", indexController.Index)
}
