package controller

import (
    "github.com/gin-gonic/gin"
    // "github.com/deatil/lakego-admin/lakego/router"

    "github.com/deatil/lakego-admin/admin/support/controller"
)

/**
 * 首页
 *
 * @create 2021-10-11
 * @author deatil
 */
type Index struct {
    controller.Base
}

/**
 * 信息
 */
func (this *Index) Index(ctx *gin.Context) {
    this.Success(ctx, "例子信息获取成功123")
}
