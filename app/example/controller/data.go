package controller

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/admin/support/controller"
)

/**
 * 数据
 *
 * @create 2022-1-9
 * @author deatil
 */
type Data struct {
    controller.Base
}

/**
 * 信息
 */
func (this *Data) Index(ctx *gin.Context) {
    this.Fetch(ctx, "example::index", map[string]interface{}{
        "msg": "测试数据",
    })
}
