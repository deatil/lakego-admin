package route

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-monitor/monitor/controller"
)

/**
 * 路由
 */
func Route(engine *gin.RouterGroup) {
    // 系统监控
    monitorController := new(controller.Monitor)
    engine.GET("/monitor", monitorController.Index)
}
