package route

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-action-log/action-log/controller"
)

/**
 * 路由
 */
func Route(engine *gin.RouterGroup) {
    // 操作日志
    actionLogController := new(controller.ActionLog)
    engine.GET("/action-log", actionLogController.Index)
    engine.DELETE("/action-log/clear", actionLogController.Clear)
}
