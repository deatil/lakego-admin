package controller

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
)

/**
 * 使用模板
 *
 * @create 2024-4-27
 * @author deatil
 */
type View struct {
    controller.Base
}

// 首页
func (this *View) Index(ctx *gin.Context) {
    this.View(ctx, "example::index.index", map[string]any{
        "msg": "测试数据",
    })
}

// 首页
func (this *View) Index2(ctx *gin.Context) {
    this.View(ctx, "example/index/index2.html", map[string]any{
        "msg": "测试数据222",
    })
}
