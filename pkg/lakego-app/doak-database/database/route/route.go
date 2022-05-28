package route

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-database/database/controller"
)

// 路由
func Route(engine *gin.RouterGroup) {
    // 数据库管理
    databaseController := new(controller.Database)
    engine.GET("/database", databaseController.Index)
    engine.GET("/database/:name", databaseController.Detail)
    engine.POST("/database/:name/optimize", databaseController.Optimize)
    engine.POST("/database/:name/repair", databaseController.Repair)
}
