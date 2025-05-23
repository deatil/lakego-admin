package route

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak/lakego/facade"

    "app/example/controller"
)

/**
 * 常规 gin 路由
 */
func GinRoute(engine gin.IRouter) {
    engine.GET("/example", func(ctx *gin.Context) {
        // 测试自定义配置数据
        exampleData := facade.Config("example").GetString("Default")
        exampleData2 := facade.Config("example").GetString("Default2")

        ctx.JSON(200, gin.H{
            "data": "例子显示信息",
            "exampleData": exampleData,
            "exampleData2": exampleData2,
        })
    })

    // 视图
    viewController := new(controller.View)
    engine.GET("/example/view/index", viewController.Index)
    engine.GET("/example/view/index2", viewController.Index2)

}

/**
 * 后台路由
 */
func AdminRoute(engine gin.IRouter) {
    // 例子
    indexController := new(controller.Index)
    engine.GET("/example/index", indexController.Index)
}
